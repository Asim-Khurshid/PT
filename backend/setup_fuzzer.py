#!/usr/bin/env python
"""
Quick Setup Script for APK Fuzzer
Run this after pulling the fuzzer changes
"""
import os
import sys
import subprocess

def run_command(cmd, description):
    """Run a command and print status"""
    print(f"\n{'='*60}")
    print(f"  {description}")
    print(f"{'='*60}")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(result.stdout)
        print(f"✓ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Error: {e}")
        print(e.stderr)
        return False

def main():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║         FalconScan APK Fuzzer Setup Script              ║
    ║                                                          ║
    ║  This script will:                                       ║
    ║  1. Install required dependencies                        ║
    ║  2. Create database migrations                           ║
    ║  3. Apply database changes                               ║
    ║  4. Verify fuzzer installation                           ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    # Check if we're in the backend directory
    if not os.path.exists('manage.py'):
        print("\n❌ Error: Please run this script from the 'backend' directory")
        print("   cd backend")
        print("   python setup_fuzzer.py")
        sys.exit(1)
    
    # Step 1: Install dependencies
    if not run_command(
        "pip install requests>=2.31.0 urllib3>=2.0.0",
        "Installing fuzzer dependencies (requests, urllib3)"
    ):
        print("\n⚠️  Warning: Dependency installation failed. You may need to install manually:")
        print("   pip install -r requirements.txt")
    
    # Step 2: Create migrations
    if not run_command(
        "python manage.py makemigrations scans",
        "Creating database migrations for fuzzer fields"
    ):
        print("\n❌ Migration creation failed")
        sys.exit(1)
    
    # Step 3: Apply migrations
    if not run_command(
        "python manage.py migrate",
        "Applying database migrations"
    ):
        print("\n❌ Migration failed")
        sys.exit(1)
    
    # Step 4: Verify installation
    print(f"\n{'='*60}")
    print("  Verifying Fuzzer Installation")
    print(f"{'='*60}")
    
    try:
        # Try importing the fuzzer
        sys.path.insert(0, os.getcwd())
        from apps.scans.apk_fuzzer import APKFuzzer
        print("✓ APK Fuzzer module imported successfully")
        
        # Check if model fields exist
        from apps.scans.models import Scan
        scan_fields = [f.name for f in Scan._meta.get_fields()]
        
        if 'fuzzing_enabled' in scan_fields:
            print("✓ Database field 'fuzzing_enabled' exists")
        else:
            print("✗ Database field 'fuzzing_enabled' not found")
            
        if 'fuzzing_analysis' in scan_fields:
            print("✓ Database field 'fuzzing_analysis' exists")
        else:
            print("✗ Database field 'fuzzing_analysis' not found")
            
    except ImportError as e:
        print(f"✗ Import error: {e}")
        sys.exit(1)
    
    print(f"\n{'='*60}")
    print("  ✅ APK Fuzzer Setup Complete!")
    print(f"{'='*60}")
    print("\nNext Steps:")
    print("  1. Start Django server: python manage.py runserver")
    print("  2. Upload APK with fuzzing: fuzzing_enabled=true")
    print("  3. Read documentation: apps/scans/FUZZER_GUIDE.md")
    print("\nExample API Request:")
    print("""
    curl -X POST http://localhost:8000/api/scans/upload/ \\
      -H "Authorization: Bearer YOUR_TOKEN" \\
      -F "file_path=@app.apk" \\
      -F "app_name=My App" \\
      -F "fuzzing_enabled=true"
    """)
    print("\n📚 Full documentation: backend/apps/scans/FUZZER_GUIDE.md")

if __name__ == '__main__':
    main()
