#!/usr/bin/env python3
import os, re, sys, zlib, lzma, bz2, base64, marshal, dis, struct, hashlib
import multiprocessing, tempfile, argparse, subprocess, shutil, binascii, glob
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from io import BytesIO
from functools import lru_cache
from datetime import datetime

class PySOX:
    def __init__(self, path, out_dir=None, debug=False, threads=None, recursive=False):
        self.path = path
        self.out_dir = out_dir or os.path.dirname(os.path.abspath(path))
        self.debug = debug
        self.threads = threads or max(1, multiprocessing.cpu_count() - 1)
        self.recursive = recursive
        self.temp_dir = tempfile.mkdtemp(prefix="pysox_")
        self.python_magic = {
            b'\x42\x0d\x0d\x0a': 3.4, b'\x43\x0d\x0d\x0a': 3.5, 
            b'\x55\x0d\x0d\x0a': 3.7, b'\x63\x0d\x0d\x0a': 3.8,
            b'\x6f\x0d\x0d\x0a': 3.9, b'\x6f\x0e\x0d\x0a': 3.10,
            b'\x6f\x0f\x0d\x0a': 3.11, b'\x6f\x10\x0d\x0a': 3.12
        }
        self._setup()

    def _setup(self):
        try:
            subprocess.run("pip install uncompyle6 pycdc xdis > /dev/null 2>&1", shell=True)
            subprocess.run("pkg install -y binutils python > /dev/null 2>&1", shell=True)
        except: pass
    
    def _find_so_files(self):
        so_files = []
        if os.path.isfile(self.path):
            if self.path.endswith('.so') or '.cpython-' in self.path:
                so_files.append(self.path)
        else:
            # Scan directory for .so files
            pattern = "**/*.so" if self.recursive else "*.so" 
            so_files.extend(glob.glob(os.path.join(self.path, pattern), recursive=self.recursive))
            
            # Also check for .cpython-* files
            cpython_pattern = "**/*.cpython-*" if self.recursive else "*.cpython-*"
            so_files.extend(glob.glob(os.path.join(self.path, cpython_pattern), recursive=self.recursive))
        
        return sorted(list(set(so_files)))  # Ensure unique entries
        
    def _get_raw_content(self, file_path):
        with open(file_path, 'rb') as f:
            return f.read()
            
    def _segment_binary(self, data):
        segments = []
        patterns = [
            (b'import', 2048), (b'class', 2048), (b'def ', 2048),
            (b'marshal.loads', 8192), (b'exec(', 4096), (b'eval(', 4096),
            (b'\x63\x00\x00\x00', 16384)
        ]
        
        for pattern, context_size in patterns:
            for match in re.finditer(re.escape(pattern), data):
                start = max(0, match.start() - context_size)
                end = min(len(data), match.end() + context_size)
                segments.append((start, end))
        
        if data[:4] == b'\x7fELF':
            for i in range(0, len(data) - 16, 4):
                if data[i:i+7] == b'.rodata' or data[i:i+5] == b'.text':
                    section_start = max(0, i - 32)
                    section_end = min(len(data), i + 32768)
                    segments.append((section_start, section_end))
        
        if not segments:
            chunk_size = 32768
            for i in range(0, len(data), chunk_size):
                segments.append((i, min(i + chunk_size + 4096, len(data))))
                
        segments.sort()
        merged = []
        for start, end in segments:
            if not merged or start > merged[-1][1]:
                merged.append((start, end))
            else:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
                
        return [(start, end, data[start:end]) for start, end in merged]

    @lru_cache(maxsize=1024)
    def _extract_python_code(self, data_bytes):
        results = []
        
        try:
            data_str = data_bytes.decode('utf-8', 'ignore')
            
            patterns = [
                r'def\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\):\s*(?:[\s\S]{10,5000}?(?:return|pass|break|continue))',
                r'class\s+[a-zA-Z_][a-zA-Z0-9_]*(?:\([^)]*\))?:\s*(?:[\s\S]{10,8000}?(?:def\s+__|\n\S))',
                r'if\s+__name__\s*==\s*[\'"]__main__[\'"]:[\s\S]{10,3000}?(?:\n\S|$)',
                r'(?:import\s+[a-zA-Z0-9_,\s\.]+|from\s+[a-zA-Z0-9_\.]+\s+import\s+[a-zA-Z0-9_\*,\s\.]+)(?:[\s\S]{10,5000}?(?:\ndef|\nclass|\nif|\nimport|\nfrom))'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, data_str)
                if matches:
                    for match in matches:
                        if len(match) > 50 and match.count('\n') > 3:
                            clean = self._clean_code_block(match)
                            if clean and len(clean) > 50:
                                results.append(clean)
        except: pass
        
        return results

    def _decompress_strategies(self, data):
        funcs = [
            lambda d: zlib.decompress(d),
            lambda d: zlib.decompress(d, 16+zlib.MAX_WBITS),
            lambda d: zlib.decompress(d, -zlib.MAX_WBITS),
            lambda d: bz2.decompress(d),
            lambda d: lzma.decompress(d)
        ]
        
        results = []
        for i in range(0, min(64, len(data)), 8):
            for func in funcs:
                try:
                    result = func(data[i:])
                    if result and len(result) > 100:
                        results.append(result)
                except: pass
        return results

    def _unmarshal_load(self, data):
        results = []
        
        try:
            for i in range(0, min(256, len(data)), 8):
                try:
                    code_obj = marshal.loads(data[i:])
                    if hasattr(code_obj, 'co_code'):
                        with tempfile.NamedTemporaryFile(suffix='.pyc', delete=False) as tf:
                            tf.write(b'\x6f\x0f\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                            tf.write(data[i:])
                            tf_path = tf.name
                        
                        py_path = f"{tf_path}.py"
                        for cmd in [
                            f"uncompyle6 -o {py_path} {tf_path} 2>/dev/null",
                            f"pycdc {tf_path} > {py_path} 2>/dev/null"
                        ]:
                            try:
                                subprocess.run(cmd, shell=True, timeout=5)
                                if os.path.exists(py_path) and os.path.getsize(py_path) > 50:
                                    with open(py_path, 'r') as f:
                                        results.append(f.read())
                                    break
                            except: pass
                            
                        for p in [tf_path, py_path]:
                            if os.path.exists(p):
                                try: os.unlink(p)
                                except: pass
                except: pass
        except: pass
        
        return results

    def _clean_code_block(self, code):
        try:
            code = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1F\x7F-\xFF]', '', code)
            
            replacements = [
                (r'print\s+([^(].*?)$', r'print(\1)'),
                (r'\n[ \t]+(?=\n)', '\n'),
                (r'\n\s*\n\s*\n+', '\n\n'),
                (r'"""[\s\S]*?"""', '"""..."'),
                (r"'''[\s\S]*?'''", "'''...'''"),
                (r'#.*?$', ''),
            ]
            
            for pattern, repl in replacements:
                code = re.sub(pattern, repl, code, flags=re.MULTILINE)
                
            try:
                compile(code, '<string>', 'exec')
                return code
            except:
                # Keep valid syntax lines
                lines = code.split('\n')
                good_lines = []
                for line in lines:
                    if (re.match(r'^(\s*)(def|class|if|for|while|try|except|import|from|return|with)\s', line) or
                        re.match(r'^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=', line)):
                        good_lines.append(line)
                return '\n'.join(good_lines) if good_lines else code
        except:
            return code

    def _process_chunk(self, chunk_data):
        results = []
        
        # Fast check - skip chunks unlikely to have Python
        if b'python' not in chunk_data.lower() and b'def ' not in chunk_data and b'class ' not in chunk_data:
            check_content = chunk_data[:4096] + chunk_data[-4096:] if len(chunk_data) > 8192 else chunk_data
            if all(pattern not in check_content.lower() for pattern in 
                  [b'import', b'from ', b'def ', b'class ', b'.py', b'marshal', b'exec(']):
                return []
        
        # Strategy 1: Extract Python code directly
        code_blocks = self._extract_python_code(chunk_data)
        if code_blocks:
            results.extend(code_blocks)
        
        # Strategy 2: Look for Python bytecode/pyc files
        for magic, version in self.python_magic.items():
            positions = [m.start() for m in re.finditer(re.escape(magic), chunk_data)]
            for pos in positions:
                # Extract enough for a pyc file
                pyc_data = chunk_data[pos:pos+16384]
                
                # Try to decompile with uncompyle6
                with tempfile.NamedTemporaryFile(suffix=f'.{version}.pyc', delete=False) as tf:
                    tf.write(pyc_data)
                    pyc_path = tf.name
                
                py_path = f"{pyc_path}.py"
                try:
                    subprocess.run(f"uncompyle6 -o {py_path} {pyc_path} 2>/dev/null", 
                                   shell=True, timeout=5)
                    
                    if os.path.exists(py_path) and os.path.getsize(py_path) > 50:
                        with open(py_path, 'r') as f:
                            results.append(f.read())
                except: pass
                
                # Cleanup
                for p in [pyc_path, py_path]:
                    if os.path.exists(p):
                        try: os.unlink(p)
                        except: pass
        
        # Strategy 3: Try decompression to find obfuscated/compressed code
        decompressed = self._decompress_strategies(chunk_data)
        for data in decompressed:
            # Check if decompressed data looks like Python
            try:
                text = data.decode('utf-8', 'ignore')
                if 'def ' in text or 'class ' in text or 'import ' in text:
                    code_blocks = self._extract_python_code(data)
                    if code_blocks:
                        results.extend(code_blocks)
            except: pass
            
            # Check if it's marshal data
            unmarshal_results = self._unmarshal_load(data)
            if unmarshal_results:
                results.extend(unmarshal_results)
        
        # Strategy 4: Try base64 decoding
        try:
            text = chunk_data.decode('utf-8', 'ignore')
            b64_pattern = r'[A-Za-z0-9+/]{30,}={0,3}'
            for match in re.finditer(b64_pattern, text):
                try:
                    decoded = base64.b64decode(match.group())
                    if len(decoded) > 100:
                        # Check if decoded data is Python code or compressed
                        decompressed = self._decompress_strategies(decoded)
                        for data in decompressed:
                            code_blocks = self._extract_python_code(data)
                            if code_blocks:
                                results.extend(code_blocks)
                        
                        # Also try unmarshal
                        unmarshal_results = self._unmarshal_load(decoded)
                        if unmarshal_results:
                            results.extend(unmarshal_results)
                except: pass
        except: pass
        
        return results

    def process_file(self, file_path):
        """Process a single .so file"""
        output_name = f"{os.path.splitext(os.path.basename(file_path))[0]}_extracted.py"
        output_path = os.path.join(self.out_dir, output_name)
        
        print(f"🔍 Analyzing file: {file_path}")
        
        try:
            raw_content = self._get_raw_content(file_path)
            segments = self._segment_binary(raw_content)
            
            print(f"  ↳ Found {len(segments)} code segments")
            
            all_code = []
            with ProcessPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self._process_chunk, segment[2]) for segment in segments]
                
                completed = 0
                for future in futures:
                    try:
                        results = future.result()
                        all_code.extend(results)
                        completed += 1
                        
                        # Update progress 
                        progress = completed / len(segments) * 100
                        print(f"\r    ⏳ {progress:.1f}% complete - Found {len(all_code)} code blocks", end="")
                    except Exception as e:
                        if self.debug:
                            print(f"\nError: {e}")
                print()  # Newline after progress
                        
            # Deduplicate code blocks
            unique_blocks = []
            seen_hashes = set()
            
            for block in all_code:
                # Generate hash to detect duplicates - normalize whitespace
                block_hash = hashlib.md5(re.sub(r'\s+', ' ', block).encode()).hexdigest()
                
                if block_hash not in seen_hashes:
                    seen_hashes.add(block_hash)
                    unique_blocks.append(block)
            
            # Sort by length (longer blocks are usually more complete)
            unique_blocks.sort(key=len, reverse=True)
            
            # Write final output
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'w') as f:
                f.write(f"#!/usr/bin/env python3\n# Extracted from {file_path} with PySOX v5\n\n")
                
                for i, block in enumerate(unique_blocks):
                    f.write(f"# {'='*20} BLOCK {i+1} {'='*20}\n")
                    f.write(block.strip() + "\n\n")
            
            print(f"  ✅ Extracted {len(unique_blocks)} code blocks to {output_path}")
            return True, output_path
            
        except Exception as e:
            print(f"  ❌ Failed to process {file_path}: {str(e)}")
            return False, None

    def batch_process(self):
        """Process all .so files"""
        so_files = self._find_so_files()
        
        if not so_files:
            print(f"❌ No .so files found in {self.path}")
            return []
        
        print(f"📦 Found {len(so_files)} file(s) to process")
        
        results = []
        for i, file_path in enumerate(so_files):
            print(f"\n[{i+1}/{len(so_files)}] Processing {os.path.basename(file_path)}")
            success, output_path = self.process_file(file_path)
            if success:
                results.append(output_path)
        
        # Clean up
        try:
            shutil.rmtree(self.temp_dir)
        except: pass
        
        print(f"\n🎉 BATCH PROCESSING COMPLETE")
        print(f"✅ Successfully processed {len(results)}/{len(so_files)} files")
        
        return results

def main():
    parser = argparse.ArgumentParser(description="PySOX v5 - Batch Extract Python from .so files")
    parser.add_argument("path", help="Path to .so file or directory containing .so files")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, help="Number of threads per file")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively search directories")
    parser.add_argument("-d", "--debug", action="store_true", help="Debug mode")
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"❌ Path not found: {args.path}")
        return 1
    
    try:
        start_time = datetime.now()
        extractor = PySOX(args.path, args.output, args.debug, args.threads, args.recursive)
        results = extractor.batch_process()
        elapsed = (datetime.now() - start_time).total_seconds()
        
        print(f"\n⏱️ Total processing time: {elapsed:.2f} seconds")
        
        if results:
            print("\n📋 Processed files:")
            for i, path in enumerate(results):
                print(f"  {i+1}. {path}")
                
        return 0
    except KeyboardInterrupt:
        print("\n🛑 Processing canceled")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())