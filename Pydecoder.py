#!/usr/bin/env python3
# PyDecoder v2.0: Ultimate Python Decompiler & Analyzer for Termux
# Supports: py, pyc, so, pyo, pyd, zip/egg/whl, PyInstaller, Pyarmor

import os
import sys
import argparse
import tempfile
import shutil
import subprocess
import binascii
import threading
import concurrent.futures
import re
import time
from pathlib import Path
from termcolor import colored
from tqdm import tqdm

try:
    import magic
except ImportError:
    # Fallback method if python-magic not available
    def identify_by_header(file_path):
        with open(file_path, 'rb') as f:
            header = f.read(16)
            if header[:2] in [b'\x03\xf3', b'\x42\x0d', b'\x00\x00']:
                return "pyc"
            ext = os.path.splitext(file_path)[1].lower()
            return ext[1:] if ext else "unknown"
    magic = None

VERSION = "2.0"
TEMP_DIR = tempfile.mkdtemp(prefix="pydecoder_")
SUCCESS_COUNT = 0
FAIL_COUNT = 0
MAX_WORKERS = min(os.cpu_count() or 1, 8)  # Limit to 8 threads max

# --- UTILS ---
def banner():
    print(colored(f"""
╔══════════════════════════════════════════════╗
║ PyDecoder v{VERSION} - Ultimate Python Decoder     ║
║ Advanced auto decompiler for Python binaries  ║
╚══════════════════════════════════════════════╝
    """, 'cyan'))

def check_dependencies(silent=False):
    """Check and install required dependencies - fast path"""
    required = {
        'pip': ['uncompyle6', 'decompyle3', 'pycdc', 'pyinstxtractor', 'tqdm', 'termcolor'],
        'pkg': ['python', 'file', 'binutils', 'clang', 'git', 'cmake']
    }
    
    # Fast install of missing dependencies
    try:
        if not silent:
            print(colored("[*] Checking dependencies...", 'yellow'))
        
        # Try import decompilers
        missing_pip = []
        for dep in required['pip']:
            try:
                if dep == 'pycdc':
                    # Check if pycdc executable exists
                    if not shutil.which('pycdc'):
                        missing_pip.append(dep)
                else:
                    __import__(dep.replace('-', '_'))
            except ImportError:
                missing_pip.append(dep)
        
        if missing_pip and not silent:
            print(colored(f"[*] Installing pip packages: {' '.join(missing_pip)}", 'yellow'))
            subprocess.run([sys.executable, '-m', 'pip', 'install', '-q'] + missing_pip, 
                          stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        return True
    except Exception as e:
        if not silent:
            print(colored(f"[!] Setup error: {e}", 'red'))
        return False

def identify_file_type(file_path):
    """Fast identification of file types with heuristics"""
    ext = os.path.splitext(file_path)[1].lower()
    
    # Quick extension check
    if ext == '.py':
        return "py"
    elif ext in ['.pyc', '.pyo']:
        return "pyc"
    elif ext == '.so':
        return "so"
    elif ext == '.pyd':
        return "pyd"
    elif ext in ['.zip', '.egg', '.whl']:
        return "package"
    elif ext == '.exe':
        return "exe"
    
    # Advanced check for no/wrong extension
    try:
        # Read first 16 bytes to check for magic numbers
        with open(file_path, 'rb') as f:
            header = f.read(16)
        
        # Check for Python bytecode
        if header[:2] in [b'\x03\xf3', b'\x42\x0d', b'\x00\x00']:
            return "pyc"
        
        # Check for PyInstaller
        if b'MEI\014\013\012\013\016' in header:
            return "exe"
        
        # Use magic if available
        if magic:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            
            if 'python' in file_type:
                if 'script' in file_type:
                    return "py"
                elif 'bytecode' in file_type:
                    return "pyc"
            elif 'executable' in file_type:
                return "exe"
            elif 'shared object' in file_type or 'dynamically linked' in file_type:
                return "so"
        
        # Last resort - check content for Python patterns
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024)
                if re.search(r'(import\s+|from\s+\w+\s+import|def\s+\w+\s*\(|class\s+\w+\s*:)', content):
                    return "py"
                # Check for compiled header but saved with wrong extension
                if "PYZ" in content or "PYC" in content:
                    return "pyc"
        except:
            pass
        
        return "unknown"
        
    except Exception:
        return "unknown"

# --- DECODERS ---
def decompile_pyc(file_path, output_dir, verbose=False):
    """Multi-engine decompiler for Python bytecode"""
    global SUCCESS_COUNT, FAIL_COUNT
    
    if verbose:
        print(colored(f"[*] Decompiling {os.path.basename(file_path)}...", 'yellow'))
    
    file_size = os.path.getsize(file_path)
    base_name = os.path.basename(file_path).rsplit('.', 1)[0]
    output_file = os.path.join(output_dir, base_name + '.py')
    
    # For very small files, probably header only, not worth decompiling
    if file_size < 100:
        with open(output_file, 'w') as f:
            f.write(f"# File too small to be valid Python bytecode ({file_size} bytes)")
        FAIL_COUNT += 1
        return False
    
    # Get Python version from file header
    python_version = None
    try:
        with open(file_path, 'rb') as f:
            magic_bytes = f.read(4)
            # Simple mapping of common Python magic numbers
            magic_map = {
                b'\x03\xf3': '2.7',
                b'\xe3\x0c': '3.4',
                b'\x33\x0d': '3.5',
                b'\x33\x0e': '3.6',
                b'\x42\x0d': '3.7',
                b'\x42\x0e': '3.8',
                b'\x42\x0f': '3.9',
                b'\x4f\x0d': '3.10',
                b'\x4f\x0e': '3.11',
                b'\x6f\x0d': '3.12'
            }
            if magic_bytes[:2] in magic_map:
                python_version = magic_map[magic_bytes[:2]]
                if verbose:
                    print(colored(f"  → Detected Python {python_version} bytecode", 'cyan'))
    except:
        pass
    
    # Try decompilers based on Python version
    decompilers = []
    
    # Select decompilers based on Python version
    if python_version:
        version = float(python_version) if '.' in python_version else int(python_version)
        if version <= 2.7:
            decompilers = ['uncompyle6', 'uncompyle2', 'pycdc']
        elif version <= 3.8:
            decompilers = ['uncompyle6', 'decompyle3', 'pycdc']
        elif version <= 3.9:
            decompilers = ['decompyle3', 'pycdc']
        else:  # 3.10+
            decompilers = ['pycdc']
    else:
        # Try all decompilers if version unknown
        decompilers = ['uncompyle6', 'decompyle3', 'pycdc']
    
    # Try each decompiler
    for decompiler in decompilers:
        try:
            if decompiler == 'uncompyle6':
                cmd = ['uncompyle6', '-o', output_file, file_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if os.path.exists(output_file) and os.path.getsize(output_file) > 10:
                    if verbose:
                        print(colored(f"[+] Successfully decompiled with uncompyle6", 'green'))
                    SUCCESS_COUNT += 1
                    return True
            
            elif decompiler == 'decompyle3':
                cmd = [sys.executable, '-m', 'decompyle3', '-o', output_file, file_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if os.path.exists(output_file) and os.path.getsize(output_file) > 10:
                    if verbose:
                        print(colored(f"[+] Successfully decompiled with decompyle3", 'green'))
                    SUCCESS_COUNT += 1
                    return True
            
            elif decompiler == 'pycdc':
                cmd = ['pycdc', file_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.stdout and len(result.stdout) > 10:
                    with open(output_file, 'w') as f:
                        f.write(result.stdout)
                    if verbose:
                        print(colored(f"[+] Successfully decompiled with pycdc", 'green'))
                    SUCCESS_COUNT += 1
                    return True
            
            elif decompiler == 'uncompyle2':
                cmd = ['uncompyle2', '-o', output_file, file_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if os.path.exists(output_file) and os.path.getsize(output_file) > 10:
                    if verbose:
                        print(colored(f"[+] Successfully decompiled with uncompyle2", 'green'))
                    SUCCESS_COUNT += 1
                    return True
                    
        except (subprocess.TimeoutExpired, Exception) as e:
            if verbose:
                print(colored(f"  ⚠ {decompiler} failed: {e}", 'red'))
    
    # If all decompilers fail, save the bytecode dump
    try:
        bytecode_file = output_file + '.bytecode'
        with open(file_path, 'rb') as f:
            try:
                # Skip header (8, 12, or 16 bytes depending on version)
                f.seek(16)
                bytecode = f.read()
            except:
                # If seeking fails, read from beginning
                f.seek(0)
                bytecode = f.read()
        
        # Try to recover some information from the bytecode
        with open(bytecode_file, 'w') as f:
            f.write("# Failed to decompile. Bytecode dump:\n\n")
            try:
                hex_dump = binascii.hexlify(bytecode).decode('utf-8')
                f.write(hex_dump[:1000] + "...\n")  # Limit size
                
                # Try to extract strings from the bytecode
                strings = re.findall(b'[\x20-\x7E]{4,}', bytecode)
                if strings:
                    f.write("\n\n# Extracted strings from bytecode:\n")
                    for s in strings[:100]:  # Limit to 100 strings
                        try:
                            f.write(f"#   {s.decode('utf-8')}\n")
                        except:
                            pass
            except:
                f.write("# Error creating bytecode dump")
        
        # Create a stub file with import statements found in bytecode
        with open(output_file, 'w') as f:
            f.write("# Failed to fully decompile this file\n")
            f.write("# This is a stub with extracted imports and function names\n\n")
            
            # Extract possible imports and functions from bytecode strings
            imports = []
            functions = []
            for s in strings:
                try:
                    decoded = s.decode('utf-8')
                    if decoded.startswith("import ") or "from " in decoded and " import " in decoded:
                        imports.append(decoded)
                    elif re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', decoded) and not decoded.startswith("__"):
                        functions.append(decoded)
                except:
                    pass
            
            # Write extracted imports
            if imports:
                f.write("# Possible imports:\n")
                for imp in set(imports):
                    f.write(f"{imp}\n")
                f.write("\n")
            
            # Write stub functions
            if functions:
                f.write("# Possible functions or classes:\n")
                for func in set(functions):
                    if len(func) > 3 and func.isalnum():
                        f.write(f"def {func}():\n    pass\n\n")
                f.write("\n")
                
            f.write("# See the .bytecode file for more information\n")
        
        FAIL_COUNT += 1
        return False
    except Exception as e:
        if verbose:
            print(colored(f"[!] Bytecode extraction failed: {e}", 'red'))
        FAIL_COUNT += 1
        return False

def analyze_so_file(file_path, output_dir, verbose=False):
    """Enhanced analysis of shared object files"""
    global SUCCESS_COUNT, FAIL_COUNT
    
    if verbose:
        print(colored(f"[*] Analyzing SO file {os.path.basename(file_path)}...", 'yellow'))
    
    base_name = os.path.basename(file_path)
    output_file = os.path.join(output_dir, base_name + '_analysis.txt')
    
    try:
        # Run analysis commands in parallel
        commands = {
            "symbols": ["nm", "-D", file_path],
            "info": ["file", file_path],
            "strings": ["strings", file_path],
            "readelf": ["readelf", "-a", file_path]
        }
        
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            # Start all commands in parallel
            futures = {executor.submit(subprocess.run, cmd, capture_output=True, text=True): 
                      name for name, cmd in commands.items()}
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    results[name] = result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
                except Exception as e:
                    results[name] = f"Failed to run: {e}"
        
        # Extract Python-related content
        python_strings = []
        if "strings" in results:
            for line in results["strings"].splitlines():
                if any(keyword in line for keyword in 
                       ['import ', 'def ', 'class ', 'python', '__main__', '__init__', '.py']):
                    python_strings.append(line)
        
        # Write analysis to file
        with open(output_file, 'w') as out:
            out.write(f"=== ANALYSIS OF {base_name} ===\n\n")
            
            if "info" in results:
                out.write("=== FILE INFO ===\n")
                out.write(results["info"] + "\n\n")
            
            if "symbols" in results:
                out.write("=== SYMBOLS ===\n")
                
                # Extract Python API and function symbols
                py_symbols = []
                for line in results["symbols"].splitlines():
                    if 'Py' in line or 'py' in line:
                        py_symbols.append(line)
                
                if py_symbols:
                    out.write("--- PYTHON SYMBOLS ---\n")
                    out.write('\n'.join(py_symbols) + "\n\n")
                
                out.write("--- ALL SYMBOLS ---\n")
                out.write(results["symbols"] + "\n\n")
            
            if python_strings:
                out.write("=== PYTHON CODE FRAGMENTS ===\n")
                out.write('\n'.join(python_strings) + "\n\n")
            
            if "readelf" in results:
                out.write("=== ELF ANALYSIS ===\n")
                out.write(results["readelf"][:5000] + "...\n\n")  # Limit size
        
        # Generate Python wrapper for the .so file
        wrapper_file = os.path.join(output_dir, base_name.split('.')[0] + '_wrapper.py')
        with open(wrapper_file, 'w') as f:
            f.write(f"""# Auto-generated wrapper for {base_name}
import ctypes
import os

# Load the shared object
_lib_path = os.path.abspath("{base_name}")
_lib = ctypes.CDLL(_lib_path)

# Extract function names from analysis
# - Edit parameter types and return types as needed
""")
            # Extract function names from symbols
            if "symbols" in results:
                func_count = 0
                for line in results["symbols"].splitlines():
                    if ' T ' in line or ' t ' in line:  # Text symbols (functions)
                        parts = line.split()
                        if len(parts) >= 3:
                            func_name = parts[-1]
                            if not func_name.startswith('_') and '.' not in func_name:
                                f.write(f"""
def {func_name}(*args):
    \"\"\"Wrapper for {func_name} function
    Edit parameters and return types as needed
    \"\"\"
    # Example: _lib.{func_name}.argtypes = [ctypes.c_int, ctypes.c_char_p]
    # Example: _lib.{func_name}.restype = ctypes.c_int
    return _lib.{func_name}(*args)
""")
                                func_count += 1
                                if func_count >= 10:  # Limit to 10 functions
                                    break
            
            f.write("""
# Usage example:
if __name__ == "__main__":
    print("Shared object wrapper example")
    # Example: result = function_name(arg1, arg2)
""")
        
        SUCCESS_COUNT += 1
        return True
    except Exception as e:
        if verbose:
            print(colored(f"[!] Analysis failed: {e}", 'red'))
        
        # Create minimal output on failure
        with open(output_file, 'w') as f:
            f.write(f"Failed to analyze {base_name}: {e}\n")
            f.write("Try using 'readelf -a' and 'strings' commands manually.")
        
        FAIL_COUNT += 1
        return False

def extract_package(file_path, output_dir, verbose=False):
    """Extract and analyze Python packages with threading"""
    global SUCCESS_COUNT, FAIL_COUNT
    
    if verbose:
        print(colored(f"[*] Extracting package {os.path.basename(file_path)}...", 'yellow'))
    
    package_dir = os.path.join(output_dir, os.path.basename(file_path) + '_extracted')
    os.makedirs(package_dir, exist_ok=True)
    
    try:
        # Extract the package
        try:
            shutil.unpack_archive(file_path, package_dir)
        except Exception as e:
            if verbose:
                print(colored(f"  ⚠ Standard extraction failed, trying direct ZIP extract: {e}", 'yellow'))
            # Try direct ZIP extract as fallback
            subprocess.run(['unzip', '-q', '-o', file_path, '-d', package_dir], 
                          stderr=subprocess.DEVNULL)
        
        # Find Python files
        py_files = []
        pyc_files = []
        so_files = []
        
        for root, _, files in os.walk(package_dir):
            for file in files:
                full_path = os.path.join(root, file)
                if file.endswith('.py'):
                    py_files.append(full_path)
                elif file.endswith('.pyc') or file.endswith('.pyo'):
                    pyc_files.append(full_path)
                elif file.endswith('.so') or file.endswith('.pyd'):
                    so_files.append(full_path)
        
        if verbose:
            print(colored(f"  → Found {len(py_files)} .py, {len(pyc_files)} .pyc, {len(so_files)} .so files", 'cyan'))
        
        # Process files in parallel with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Process .pyc files
            if pyc_files:
                if verbose:
                    print(colored(f"  → Decompiling {len(pyc_files)} bytecode files...", 'cyan'))
                futures = []
                for pyc_file in pyc_files:
                    futures.append(executor.submit(
                        decompile_pyc, pyc_file, os.path.dirname(pyc_file), False))
                
                # Wait for completion with progress bar if verbose
                if verbose and len(pyc_files) > 3:
                    for _ in tqdm(concurrent.futures.as_completed(futures), 
                                 total=len(futures), desc="Decompiling PYC"):
                        pass
                else:
                    concurrent.futures.wait(futures)
                
            # Process .so files
            if so_files:
                if verbose:
                    print(colored(f"  → Analyzing {len(so_files)} binary files...", 'cyan'))
                futures = []
                for so_file in so_files:
                    futures.append(executor.submit(
                        analyze_so_file, so_file, os.path.dirname(so_file), False))
                
                # Wait for completion with progress bar if verbose
                if verbose and len(so_files) > 3:
                    for _ in tqdm(concurrent.futures.as_completed(futures), 
                                 total=len(futures), desc="Analyzing SO"):
                        pass
                else:
                    concurrent.futures.wait(futures)
        
        # Generate package summary
        summary_file = os.path.join(package_dir, "_PACKAGE_SUMMARY.txt")
        with open(summary_file, 'w') as f:
            f.write(f"Package: {os.path.basename(file_path)}\n")
            f.write(f"Extracted to: {package_dir}\n\n")
            f.write(f"Python files: {len(py_files)}\n")
            f.write(f"Bytecode files: {len(pyc_files)}\n")
            f.write(f"Binary files: {len(so_files)}\n\n")
            
            if py_files:
                f.write("=== Python modules found ===\n")
                for py_file in sorted(py_files)[:20]:  # Limit to 20 entries
                    rel_path = os.path.relpath(py_file, package_dir)
                    f.write(f"- {rel_path}\n")
                if len(py_files) > 20:
                    f.write(f"... and {len(py_files) - 20} more\n")
            
            # Add imports summary if possible
            try:
                imports = {}
                for py_file in py_files[:50]:  # Limit to first 50 py files
                    try:
                        with open(py_file, 'r', encoding='utf-8', errors='ignore') as pf:
                            content = pf.read()
                            for match in re.finditer(r'import\s+(\w+)|from\s+(\w+)', content):
                                module = match.group(1) or match.group(2)
                                imports[module] = imports.get(module, 0) + 1
                    except:
                        pass
                
                if imports:
                    f.write("\n=== Most common imports ===\n")
                    for module, count in sorted(imports.items(), key=lambda x: x[1], reverse=True)[:15]:
                        f.write(f"- {module}: {count} times\n")
            except:
                pass
        
        SUCCESS_COUNT += 1
        return True
    except Exception as e:
        if verbose:
            print(colored(f"[!] Package extraction failed: {e}", 'red'))
        
        # Create error file
        with open(os.path.join(output_dir, f"{os.path.basename(file_path)}_error.txt"), 'w') as f:
            f.write(f"Failed to extract {file_path}: {e}\n")
        
        FAIL_COUNT += 1
        return False

def decompile_pyinstaller(file_path, output_dir, verbose=False):
    """Extract and decompile PyInstaller executables"""
    global SUCCESS_COUNT, FAIL_COUNT
    
    if verbose:
        print(colored(f"[*] Extracting PyInstaller executable {os.path.basename(file_path)}...", 'yellow'))
    
    base_name = os.path.basename(file_path)
    extract_dir = os.path.join(output_dir, f"{base_name}_extracted")
    os.makedirs(extract_dir, exist_ok=True)
    
    try:
        # First try PyInstaller Extractor
        try:
            cmd = [sys.executable, '-m', 'pyinstxtractor', file_path]
            result = subprocess.run(cmd, cwd=extract_dir, capture_output=True, text=True)
            
            # Check if extraction succeeded
            success = False
            for root, dirs, files in os.walk(extract_dir):
                if "PYZ-00.pyz_extracted" in dirs or "pyiboot01_bootstrap.py" in files:
                    success = True
                    break
            
            if not success:
                if verbose:
                    print(colored("  ⚠ PyInstaller extraction failed, trying alternative method", 'yellow'))
                raise Exception("Extraction failed")
                
        except Exception:
            # Fallback - try to use a direct method
            # Check if it's actually a PyInstaller executable
            with open(file_path, 'rb') as f:
                content = f.read(1024*1024)  # Read first MB
            
            if b'PYZ' not in content and b'PyInstaller' not in content:
                raise Exception("Not a valid PyInstaller executable")
            
            # Try universal extractor method
            if sys.platform == 'win32':
                subprocess.run(['7z', 'x', file_path, f'-o{extract_dir}', '-y'], 
                              stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            else:
                # For Linux/Termux
                subprocess.run(['7z', 'x', file_path, f'-o{extract_dir}', '-y'], 
                              stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        
        # Find and decompile PYC files
        pyc_files = []
        for root, _, files in os.walk(extract_dir):
            for file in files:
                if file.endswith('.pyc') or file.endswith('.pyo'):
                    pyc_files.append(os.path.join(root, file))
        
        if not pyc_files:
            # Look for PYZ files (PyInstaller archives)
            pyz_files = []
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    if file.endswith('.pyz'):
                        pyz_files.append(os.path.join(root, file))
            
            # Extract PYZ files (they're actually ZIP files)
            for pyz_file in pyz_files:
                pyz_dir = pyz_file + "_extracted"
                os.makedirs(pyz_dir, exist_ok=True)
                try:
                    shutil.unpack_archive(pyz_file, pyz_dir, 'zip')
                except:
                    subprocess.run(['unzip', '-q', '-o', pyz_file, '-d', pyz_dir], 
                                  stderr=subprocess.DEVNULL)
                
                # Find PYC files in extracted PYZ
                for root, _, files in os.walk(pyz_dir):
                    for file in files:
                        if file.endswith('.pyc') or file.endswith('.pyo') or '.pyc.' in file:
                            pyc_files.append(os.path.join(root, file))
        
        if verbose:
            print(colored(f"  → Found {len(pyc_files)} Python bytecode files", 'cyan'))
        
        # Process files with a thread pool
        decompiled_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for pyc_file in pyc_files:
                futures.append(executor.submit(
                    decompile_pyc, pyc_file, os.path.dirname(pyc_file), False))
            
            # Wait for completion with progress bar if verbose
            if verbose and len(pyc_files) > 3:
                for _ in tqdm(concurrent.futures.as_completed(futures), 
                             total=len(futures), desc="Decompiling"):
                    pass
            else:
                for future in concurrent.futures.as_completed(futures):
                    if future.result():
                        decompiled_count += 1
        
        # Generate summary
        summary_file = os.path.join(extract_dir, "_PYINSTALLER_SUMMARY.txt")
        with open(summary_file, 'w') as f:
            f.write(f"PyInstaller Executable: {base_name}\n")
            f.write(f"Extracted to: {extract_dir}\n\n")
            f.write(f"Total bytecode files found: {len(pyc_files)}\n")
            f.write(f"Successfully decompiled: {decompiled_count}\n\n")
            
            # Try to find the entry point
            entry_candidates = ['__main__', 'main', 'run', 'start', 'app']
            entry_points = []
            
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    if file.endswith('.py') and file.split('.')[0] in entry_candidates:
                        entry_points.append(os.path.join(root, file))
            
            if entry_points:
                f.write("=== Possible Entry Points ===\n")
                for entry in entry_points:
                    rel_path = os.path.relpath(entry, extract_dir)
                    f.write(f"- {rel_path}\n")
        
        if decompiled_count > 0:
            SUCCESS_COUNT += 1
            return True
        else:
            FAIL_COUNT += 1
            return False
            
    except Exception as e:
        if verbose:
            print(colored(f"[!] PyInstaller extraction failed: {e}", 'red'))
        
        # Create error file
        with open(os.path.join(output_dir, f"{base_name}_error.txt"), 'w') as f:
            f.write(f"Failed to extract PyInstaller executable {file_path}: {e}\n")
        
        FAIL_COUNT += 1
        return False

def process_pyarmor(file_path, output_dir, verbose=False):
    """Attempt to detect and process PyArmor protected files"""
    global SUCCESS_COUNT, FAIL_COUNT
    
    if verbose:
        print(colored(f"[*] Processing possible PyArmor file {os.path.basename(file_path)}...", 'yellow'))
    
    base_name = os.path.basename(file_path)
    output_file = os.path.join(output_dir, base_name + '.deobfuscated.py')
    
    # Check if it's a PyArmor file
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(5000)  # Read the first 5000 chars
            
        # PyArmor detection patterns
        pyarmor_patterns = [
            r'__pyarmor__',
            r'pyarmor_runtime',
            r'__armor_enter__',
            r'__armor_exit__'
        ]
        
        is_pyarmor = any(re.search(pattern, content) for pattern in pyarmor_patterns)
        
        if not is_pyarmor:
            if verbose:
                print(colored("  → Not a PyArmor protected file, skipping", 'yellow'))
            return False
        
        if verbose:
            print(colored("  → PyArmor protection detected", 'cyan'))
        
        # Extract the loader part (not obfuscated) and any hardcoded strings
        with open(output_file, 'w') as f:
            f.write("# PyArmor protected file - partial extraction\n")
            f.write("# Original file: " + base_name + "\n\n")
            
            # Extract the loader section
            loader_match = re.search(r'(def\s+__bootstrap__.*?)(?=\n\n)', content, re.DOTALL)
            if loader_match:
                f.write("# === Loader Code ===\n")
                f.write(loader_match.group(1) + "\n\n")
            
            # Extract imports
            imports = re.findall(r'^(import\s+.*?$|from\s+.*?$)', content, re.MULTILINE)
            if imports:
                f.write("# === Imports ===\n")
                f.write("\n".join(imports) + "\n\n")
            
            # Extract strings
            strings = re.findall(r'[\'"]([^\'"]{5,})[\'"]', content)
            if strings:
                f.write("# === Extracted Strings ===\n")
                unique_strings = set()
                for s in strings:
                    # Filter out binary garbage
                    if all(32 <= ord(c) < 127 for c in s) and len(s.strip()) > 0:
                        unique_strings.add(s)
                
                for s in sorted(unique_strings):
                    f.write(f"# {s}\n")
            
            # Add note
            f.write("\n# Note: PyArmor protection requires the encryption key to fully deobfuscate.\n")
            f.write("# This is only a partial extraction of non-obfuscated components.\n")
        
        # Also create a Python file that can extract runtime information
        runtime_extractor = os.path.join(output_dir, base_name + '.runtime_extractor.py')
        with open(runtime_extractor, 'w') as f:
            f.write(f"""# PyArmor Runtime Extractor
# Run this in the same directory as {base_name}

import sys
import os
import types
import importlib.util
import marshal

# Store original builtins and marshal.loads
original_marshal_loads = marshal.loads
extracted_code_objects = []

# Monkey patch marshal.loads to intercept code objects
def patched_marshal_loads(data):
    code_obj = original_marshal_loads(data)
    if isinstance(code_obj, types.CodeType):
        extracted_code_objects.append(code_obj)
    return code_obj

# Set up hooks
marshal.loads = patched_marshal_loads

# Import the protected module
module_path = "{base_name}"
module_name = os.path.splitext(module_path)[0]

try:
    print(f"[*] Attempting to import {{module_name}}...")
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    
    # This is where PyArmor will decrypt and load code
    spec.loader.exec_module(module)
    
    print(f"[+] Successfully imported module")
    print(f"[+] Extracted {{len(extracted_code_objects)}} code objects")
    
    # Save extracted code objects
    output_dir = "extracted_code"
    os.makedirs(output_dir, exist_ok=True)
    
    for i, code_obj in enumerate(extracted_code_objects):
        output_file = os.path.join(output_dir, f"code_{{i}}.py")
        with open(output_file, 'w') as f:
            f.write(f"# Extracted code object {{i}}\\n")
            try:
                f.write(f"# Name: {{code_obj.co_name}}\\n")
                f.write(f"# Filename: {{code_obj.co_filename}}\\n")
                f.write(f"# Constants: {{code_obj.co_consts}}\\n\\n")
            except:
                f.write("# Error accessing code object attributes\\n\\n")
    
    print(f"[+] Saved extracted code to {{output_dir}}/")

except Exception as e:
    print(f"[!] Error: {{e}}")
""")
        
        SUCCESS_COUNT += 1
        return True
        
    except Exception as e:
        if verbose:
            print(colored(f"[!] PyArmor processing failed: {e}", 'red'))
        FAIL_COUNT += 1
        return False

def process_file(file_path, output_dir=None, verbose=False, force_type=None):
    """Process a single file with auto-detection"""
    global SUCCESS_COUNT, FAIL_COUNT
    
    if not os.path.exists(file_path):
        print(colored(f"[!] File not found: {file_path}", 'red'))
        return False
    
    # Create output directory
    if not output_dir:
        output_dir = os.path.join(os.path.dirname(os.path.abspath(file_path)), 'pydecoder_output')
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Identify file type or use forced type
    file_type = force_type if force_type else identify_file_type(file_path)
    
    if verbose:
        print(colored(f"[*] Processing: {os.path.basename(file_path)} (type: {file_type})", 'cyan'))
    
    # Process based on file type
    if file_type == "py":
        # First check if it's a PyArmor file
        if process_pyarmor(file_path, output_dir, verbose):
            return True
        
        # Otherwise just copy the Python file
        try:
            dest = os.path.join(output_dir, os.path.basename(file_path))
            shutil.copy2(file_path, dest)
            if verbose:
                print(colored(f"[+] Copied Python source file to {dest}", 'green'))
            SUCCESS_COUNT += 1
            return True
        except Exception as e:
            if verbose:
                print(colored(f"[!] Error copying file: {e}", 'red'))
            FAIL_COUNT += 1
            return False
            
    elif file_type == "pyc":
        return decompile_pyc(file_path, output_dir, verbose)
        
    elif file_type in ["so", "pyd"]:
        return analyze_so_file(file_path, output_dir, verbose)
        
    elif file_type == "package":
        return extract_package(file_path, output_dir, verbose)
        
    elif file_type == "exe":
        return decompile_pyinstaller(file_path, output_dir, verbose)
        
    else:
        if verbose:
            print(colored(f"[!] Unsupported file type: {file_path}", 'red'))
        FAIL_COUNT += 1
        return False

def setup_environment():
    """One-time environment setup"""
    home_dir = os.path.expanduser("~")
    pydecoder_dir = os.path.join(home_dir, '.pydecoder')
    
    if not os.path.exists(pydecoder_dir):
        os.makedirs(pydecoder_dir, exist_ok=True)
        print(colored(f"[*] Created PyDecoder directory: {pydecoder_dir}", 'yellow'))
    
    # Create launcher script
    bin_dir = os.path.join(home_dir, 'bin')
    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir, exist_ok=True)
    
    launcher = os.path.join(bin_dir, 'pydecoder')
    with open(launcher, 'w') as f:
        f.write(f"""#!/data/data/com.termux/files/usr/bin/bash
python3 {os.path.abspath(__file__)} "$@"
""")
    
    os.chmod(launcher, 0o755)
    print(colored(f"[+] Created launcher script: {launcher}", 'green'))
    
    # Setup completion
    completion_file = os.path.join(pydecoder_dir, 'pydecoder_completion.sh')
    with open(completion_file, 'w') as f:
        f.write("""
_pydecoder()
{
    local cur prev words cword
    _init_completion || return

    local opts="-h --help -o --output -v --verbose -r --recursive -s --setup -i --install -f --force-type"
    local types="py pyc so pyd package exe"

    case $prev in
        -o|--output)
            _filedir -d
            return
            ;;
        -f|--force-type)
            COMPREPLY=( $(compgen -W "$types" -- "$cur") )
            return
            ;;
    esac

    if [[ $cur == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    else
        _filedir
    fi
} &&
complete -F _pydecoder pydecoder
""")
    
    # Add to bashrc if not already there
    bashrc = os.path.join(home_dir, '.bashrc')
    if os.path.exists(bashrc):
        with open(bashrc, 'r') as f:
            content = f.read()
        
        if 'pydecoder_completion.sh' not in content:
            with open(bashrc, 'a') as f:
                f.write(f'\n# PyDecoder completion\nif [ -f "{completion_file}" ]; then\n    . "{completion_file}"\nfi\n')
                print(colored("[+] Added completion to .bashrc", 'green'))
    
    print(colored("[*] You can now run 'pydecoder' from anywhere in Termux", 'yellow'))
    print(colored("[*] Start a new session or run 'source ~/.bashrc' to enable tab completion", 'yellow'))

def install_dependencies_termux():
    """Fast dependency installation for Termux"""
    try:
        print(colored("[*] Installing dependencies...", 'yellow'))
        
        # Update and install system packages
        subprocess.run(['pkg', 'update', '-y'], stdout=subprocess.DEVNULL)
        packages = ['python', 'file', 'binutils', 'clang', 'git', 'cmake', 'unzip', '7zip']
        subprocess.run(['pkg', 'install', '-y'] + packages, stdout=subprocess.DEVNULL)
        
        # Install Python packages
        pip_packages = ['uncompyle6', 'decompyle3', 'pyinstxtractor', 'tqdm', 'termcolor']
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade'] + pip_packages,
                      stdout=subprocess.DEVNULL)
        
        # Try to install python-magic (fallback to pure Python version if fails)
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'python-magic'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'python-magic-bin'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Install pycdc (bytecode decompiler)
        pycdc_dir = os.path.join(TEMP_DIR, 'pycdc')
        if not os.path.exists('/data/data/com.termux/files/usr/bin/pycdc'):
            print(colored("[*] Installing pycdc decompiler...", 'yellow'))
            subprocess.run(['git', 'clone', 'https://github.com/zrax/pycdc', pycdc_dir],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['cmake', '.'], cwd=pycdc_dir,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['make'], cwd=pycdc_dir,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            shutil.copy2(os.path.join(pycdc_dir, 'pycdc'), 
                       '/data/data/com.termux/files/usr/bin/pycdc')
            subprocess.run(['chmod', '+x', '/data/data/com.termux/files/usr/bin/pycdc'])
        
        print(colored("[+] All dependencies installed successfully", 'green'))
        return True
    except Exception as e:
        print(colored(f"[!] Dependency installation failed: {e}", 'red'))
        print(colored("[*] You can try installing dependencies manually:", 'yellow'))
        print(colored("    pkg install python file binutils clang git cmake", 'yellow'))
        print(colored("    pip install uncompyle6 decompyle3 pyinstxtractor tqdm termcolor", 'yellow'))
        return False

def process_directory(dir_path, output_dir, recursive=False, verbose=False):
    """Process all eligible files in a directory"""
    if not os.path.isdir(dir_path):
        print(colored(f"[!] Not a directory: {dir_path}", 'red'))
        return
    
    file_count = 0
    for root, _, files in os.walk(dir_path):
        for file in files:
            if file.endswith(('.py', '.pyc', '.pyo', '.so', '.pyd', '.zip', '.egg', '.whl', '.exe')):
                file_count += 1
        
        if not recursive:
            break
    
    if file_count == 0:
        print(colored(f"[!] No compatible files found in {dir_path}", 'red'))
        return
    
    print(colored(f"[*] Found {file_count} files to process in {dir_path}", 'yellow'))
    
    # Process all files with progress bar
    processed = 0
    with tqdm(total=file_count, disable=not verbose) as pbar:
        for root, _, files in os.walk(dir_path):
            rel_path = os.path.relpath(root, dir_path)
            target_dir = os.path.join(output_dir, rel_path) if rel_path != '.' else output_dir
            
            for file in files:
                if file.endswith(('.py', '.pyc', '.pyo', '.so', '.pyd', '.zip', '.egg', '.whl', '.exe')):
                    full_path = os.path.join(root, file)
                    os.makedirs(target_dir, exist_ok=True)
                    process_file(full_path, target_dir, verbose=False)
                    processed += 1
                    pbar.update(1)
            
            if not recursive:
                break
    
    print(colored(f"[+] Processed {processed} files from {dir_path}", 'green'))

def main():
    """Main function"""
    global SUCCESS_COUNT, FAIL_COUNT
    
    start_time = time.time()
    banner()
    
    parser = argparse.ArgumentParser(description='PyDecoder v2.0: Python decompiler & analyzer')
    parser.add_argument('files', nargs='*', help='Files or directories to process')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-r', '--recursive', action='store_true', help='Process directories recursively')
    parser.add_argument('-s', '--setup', action='store_true', help='Setup environment')
    parser.add_argument('-i', '--install', action='store_true', help='Install dependencies')
    parser.add_argument('-f', '--force-type', choices=['py', 'pyc', 'so', 'pyd', 'package', 'exe'], 
                      help='Force specific file type')
    
    args = parser.parse_args()
    
    # Check for setup or installation first
    if args.setup:
        setup_environment()
        sys.exit(0)
    
    if args.install:
        install_dependencies_termux()
        sys.exit(0)
    
    # Check for files
    if not args.files:
        parser.print_help()
        sys.exit(0)
    
    # Check dependencies quietly
    check_dependencies(silent=True)
    
    # Create output directory
    output_dir = args.output
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    else:
        output_dir = os.path.join(os.getcwd(), 'pydecoder_output')
        os.makedirs(output_dir, exist_ok=True)
    
    # Process all inputs
    for input_path in args.files:
        if os.path.isdir(input_path):
            process_directory(input_path, output_dir, args.recursive, args.verbose)
        elif os.path.isfile(input_path):
            process_file(input_path, output_dir, args.verbose, args.force_type)
        else:
            print(colored(f"[!] Not a valid file or directory: {input_path}", 'red'))
    
    # Summary
    elapsed = time.time() - start_time
    print(colored(f"\n┌─ Summary ───────────────────────────", 'cyan'))
    print(colored(f"│ Successful operations: {SUCCESS_COUNT}", 'green'))
    print(colored(f"│ Failed operations: {FAIL_COUNT}", 'yellow' if FAIL_COUNT == 0 else 'red'))
    print(colored(f"│ Time elapsed: {elapsed:.1f}s", 'cyan'))
    print(colored(f"│ Output directory: {output_dir}", 'cyan'))
    print(colored(f"└─────────────────────────────────────", 'cyan'))
    
    # Cleanup
    try:
        shutil.rmtree(TEMP_DIR)
    except:
        pass

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Operation canceled by user", 'yellow'))
        try:
            shutil.rmtree(TEMP_DIR)
        except:
            pass
        sys.exit(1)
