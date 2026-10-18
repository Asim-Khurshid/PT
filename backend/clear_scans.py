#!/usr/bin/env python
"""
Quick script to clear all scan data from the database.
Run this if you want to test uploading the same APK again.

Usage: python clear_scans.py
"""
import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'falconscan_backend.settings')
django.setup()

from apps.scans.models import Scan, Vulnerability, Permission, Report

def clear_all_scans():
    """Delete all scan data"""
    print("Clearing all scan data...")
    
    # Delete all related data (cascades automatically)
    scan_count = Scan.objects.count()
    vuln_count = Vulnerability.objects.count()
    perm_count = Permission.objects.count()
    report_count = Report.objects.count()
    
    Scan.objects.all().delete()
    
    print(f"✓ Deleted {scan_count} scans")
    print(f"✓ Deleted {vuln_count} vulnerabilities")
    print(f"✓ Deleted {perm_count} permissions")
    print(f"✓ Deleted {report_count} reports")
    print("\nDatabase cleared successfully!")

if __name__ == '__main__':
    response = input("This will delete ALL scans from the database. Continue? (yes/no): ")
    if response.lower() == 'yes':
        clear_all_scans()
    else:
        print("Cancelled.")
