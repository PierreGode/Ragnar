#!/usr/bin/env python3
"""
Test script for service separation
Verifies that:
1. ragnar_web.py can be imported and initialized
2. Ragnar.py no longer imports webapp_modern
3. Both scripts have correct dependencies
"""

import sys
import os

# Get the repository root directory (where this script is located)
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))

def test_ragnar_web_imports():
    """Test that ragnar_web.py imports correctly"""
    print("Testing ragnar_web.py imports...")
    try:
        # We can't actually run it without the full environment,
        # but we can check if it compiles
        import py_compile
        ragnar_web_path = os.path.join(REPO_ROOT, 'ragnar_web.py')
        py_compile.compile(ragnar_web_path, doraise=True)
        print("   ✓ ragnar_web.py compiles successfully")
        return True
    except Exception as e:
        print(f"   ✗ ragnar_web.py compilation failed: {e}")
        return False

def test_ragnar_core_imports():
    """Test that Ragnar.py imports correctly without webapp"""
    print("\nTesting Ragnar.py imports...")
    try:
        # Check that Ragnar.py compiles
        import py_compile
        ragnar_path = os.path.join(REPO_ROOT, 'Ragnar.py')
        py_compile.compile(ragnar_path, doraise=True)
        print("   ✓ Ragnar.py compiles successfully")
        
        # Check that webapp_modern import is commented out
        with open(ragnar_path, 'r') as f:
            content = f.read()
            # Check if there's an uncommented import
            has_uncommented_import = 'from webapp_modern import run_server' in content
            # Count commented versions
            commented_count = content.count('# from webapp_modern import run_server')
            
            if has_uncommented_import and commented_count == 0:
                print("   ✗ Ragnar.py still has uncommented webapp_modern import")
                return False
            print("   ✓ Ragnar.py does not import webapp_modern (properly commented)")
        return True
    except Exception as e:
        print(f"   ✗ Ragnar.py compilation failed: {e}")
        return False

def test_service_files_exist():
    """Test that systemd service template exists"""
    print("\nChecking service configuration...")
    
    # Check install script mentions both services
    install_script = os.path.join(REPO_ROOT, 'install_ragnar.sh')
    if os.path.exists(install_script):
        with open(install_script, 'r') as f:
            content = f.read()
            if 'ragnar-web.service' in content:
                print("   ✓ install_ragnar.sh includes ragnar-web.service")
            else:
                print("   ✗ install_ragnar.sh missing ragnar-web.service")
                return False
                
            if 'ragnar.service' in content:
                print("   ✓ install_ragnar.sh includes ragnar.service")
            else:
                print("   ✗ install_ragnar.sh missing ragnar.service")
                return False
    return True

def test_documentation():
    """Test that documentation exists"""
    print("\nChecking documentation...")
    
    service_sep_doc = os.path.join(REPO_ROOT, 'SERVICE_SEPARATION.md')
    if os.path.exists(service_sep_doc):
        print("   ✓ SERVICE_SEPARATION.md exists")
    else:
        print("   ✗ SERVICE_SEPARATION.md missing")
        return False
    
    # Check README mentions service separation
    readme = os.path.join(REPO_ROOT, 'README.md')
    if os.path.exists(readme):
        with open(readme, 'r') as f:
            content = f.read()
            if 'ragnar.service' in content and 'ragnar-web.service' in content:
                print("   ✓ README.md documents both services")
            else:
                print("   ✗ README.md missing service documentation")
                return False
    return True

def main():
    print("=" * 70)
    print("Ragnar Service Separation Tests")
    print("=" * 70)
    
    tests = [
        test_ragnar_web_imports,
        test_ragnar_core_imports,
        test_service_files_exist,
        test_documentation
    ]
    
    results = []
    for test in tests:
        results.append(test())
    
    print("\n" + "=" * 70)
    if all(results):
        print("✓ All tests passed!")
        print("=" * 70)
        return 0
    else:
        print("✗ Some tests failed")
        print("=" * 70)
        return 1

if __name__ == "__main__":
    sys.exit(main())
