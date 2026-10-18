"""
Background task for APK analysis
"""
from typing import Dict
from django.utils import timezone
from django.db import IntegrityError
from .models import Scan, Vulnerability, Permission, Report
from .analyzer import APKAnalyzer, ReportGenerator
from .dynamic_analyzer import DynamicAnalyzer
from .vulnerability_scanner import VulnerabilityScanner
from .pdf_generator import PDFReportGenerator
from .apk_fuzzer import APKFuzzer, extract_components_for_fuzzing, enrich_finding_for_reporting, FINDING_SEVERITY_WEIGHTS, FINDING_SOURCE_WEIGHTS

# Track cancelled scans
cancelled_scans = set()

def cancel_analysis(scan_id: int):
    """Mark a scan as cancelled"""
    cancelled_scans.add(scan_id)

def is_cancelled(scan_id: int) -> bool:
    """Check if a scan has been cancelled"""
    return scan_id in cancelled_scans

def clear_cancellation(scan_id: int):
    """Remove cancellation flag after handling"""
    cancelled_scans.discard(scan_id)


def analyze_apk(scan_id: int):
    """
    Perform static analysis on uploaded APK - Optimized for speed
    This would typically run in background (Celery/RQ)
    """
    import time
    start_time = time.time()
    
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'scanning'
        scan.started_at = timezone.now()
        
        try:
            scan.save()
        except IntegrityError as integrity_error:
            # If duplicate detected at start, check if another scan is already processing
            print(f"[ANALYSIS] Duplicate scan detected at start: {str(integrity_error)}")
            existing_scan = Scan.objects.filter(
                user=scan.user,
                hash_md5=scan.hash_md5
            ).exclude(id=scan.id).first()
            
            if existing_scan and existing_scan.status in ['scanning', 'completed']:
                print(f"[ANALYSIS] Existing scan {existing_scan.id} is already {existing_scan.status}. Aborting duplicate."
                )
                scan.delete()
                return False
            else:
                # Proceed with this scan
                scan.save(update_fields=['status', 'started_at'])
        
        print(f"[ANALYSIS] Starting analysis for scan {scan_id}")
        
        # Check if at least one analysis type is enabled
        if not scan.static_analysis_enabled and not scan.dynamic_analysis_enabled:
            print(f"[ANALYSIS] No analysis type enabled for scan {scan_id}, marking as completed")
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.save()
            return True
        
        # Check if cancelled
        if is_cancelled(scan_id):
            print(f"[ANALYSIS] Scan {scan_id} was cancelled before starting")
            clear_cancellation(scan_id)
            return False
        
        # Get APK file path
        apk_path = scan.file_path.path
        print(f"[ANALYSIS] APK path: {apk_path}")
        
        # Check if cancelled
        if is_cancelled(scan_id):
            print(f"[ANALYSIS] Scan {scan_id} was cancelled during initialization")
            clear_cancellation(scan_id)
            return False
        
        results = {'success': True, 'manifest': {}}
        manifest_data = {}
        all_vulnerabilities = []
        
        # Run static analysis if enabled
        if scan.static_analysis_enabled:
            # Initialize analyzer
            step_time = time.time()
            analyzer = APKAnalyzer(apk_path, cancel_check=lambda: is_cancelled(scan_id))
            print(f"[ANALYSIS] Analyzer initialized in {time.time() - step_time:.2f}s")
            
            # Check if cancelled
            if is_cancelled(scan_id):
                print(f"[ANALYSIS] Scan {scan_id} was cancelled after analyzer init")
                clear_cancellation(scan_id)
                return False
            
            # Run analysis (now faster with Androguard!)
            step_time = time.time()
            results = analyzer.analyze()
            print(f"[ANALYSIS] Analysis completed in {time.time() - step_time:.2f}s")
            
            # Check if cancelled
            if is_cancelled(scan_id):
                print(f"[ANALYSIS] Scan {scan_id} was cancelled after analysis")
                clear_cancellation(scan_id)
                return False

            if results.get('cancelled'):
                print(f"[ANALYSIS] Scan {scan_id} was cancelled during static analysis")
                clear_cancellation(scan_id)
                scan.status = 'failed'
                scan.error_message = 'Analysis cancelled by user'
                scan.completed_at = timezone.now()
                scan.save()
                return False
        
        if results.get('success'):
            summary = results.get('summary', {})
            all_vulnerabilities = results.get('vulnerabilities', [])
            
            # Update package name and version from manifest if not set
            manifest_data = results.get('manifest', {})
            if not scan.package_name or scan.package_name == 'unknown':
                scan.package_name = manifest_data.get('package', 'unknown')
            
            if not scan.version:
                version_name = manifest_data.get('version_name', '')
                version_code = manifest_data.get('version_code', '')
                if version_name:
                    scan.version = f"{version_name} ({version_code})" if version_code else version_name
                elif version_code:
                    scan.version = str(version_code)
            
            # Run vulnerability scanning only if static analysis is enabled
            if scan.static_analysis_enabled:
                # Run comprehensive vulnerability scanning
                step_time = time.time()
                vuln_scanner = VulnerabilityScanner()
                
                # Check if cancelled before vulnerability scanning
                if is_cancelled(scan_id):
                    print(f"[ANALYSIS] Scan {scan_id} was cancelled before vulnerability scanning")
                    clear_cancellation(scan_id)
                    return False
                
                additional_vulns = vuln_scanner.scan(
                    androguard_results=results,
                    static_analysis=results.get('static_analysis', {})
                )
                print(f"[ANALYSIS] Vulnerability scanning completed in {time.time() - step_time:.2f}s")
                print(f"[ANALYSIS] Found {len(additional_vulns)} additional vulnerabilities")
                
                # Merge vulnerabilities from analyzer and scanner
                all_vulnerabilities = results.get('vulnerabilities', []) + additional_vulns
                all_vulnerabilities = _filter_vulnerabilities(all_vulnerabilities)
                results['vulnerabilities'] = all_vulnerabilities
                
                # Recalculate severity counts
                severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                for vuln in all_vulnerabilities:
                    sev = vuln.get('severity', 'info').lower()
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                # Update scan with results
                scan.threat_level = summary.get('threat_level', 'safe')
                scan.threat_score = summary.get('risk_score', 0)
                scan.total_issues = len(all_vulnerabilities)
                
                scan.critical_issues = severity_counts.get('critical', 0)
                scan.high_issues = severity_counts.get('high', 0)
                scan.medium_issues = severity_counts.get('medium', 0)
                scan.low_issues = severity_counts.get('low', 0)
                
                # Calculate risk score using weighted formula (CVSS-inspired)
                # Base weights: Critical=25, High=15, Medium=8, Low=3
                base_score = (
                    scan.critical_issues * 25 +
                    scan.high_issues * 15 +
                    scan.medium_issues * 8 +
                    scan.low_issues * 3
                )
                
                # Add multipliers for dangerous patterns
                multiplier = 1.0
                static_analysis = results.get('static_analysis', {})
                
                # Dangerous permissions increase risk
                permissions = static_analysis.get('permissions', {})
                dangerous_perms = permissions.get('dangerous', [])
                if len(dangerous_perms) > 5:
                    multiplier += 0.2
                elif len(dangerous_perms) > 3:
                    multiplier += 0.1
                
                # Security issues increase risk
                security = static_analysis.get('security', {})
                if security.get('debuggable'):
                    multiplier += 0.15
                if security.get('allow_backup'):
                    multiplier += 0.1
                if security.get('network_security', {}).get('clear_text_traffic'):
                    multiplier += 0.15
                
                # Code issues increase risk
                code_analysis = static_analysis.get('code_analysis', {})
                if code_analysis.get('crypto_issues', 0) > 0:
                    multiplier += 0.1
                if code_analysis.get('hardcoded_secrets', 0) > 0:
                    multiplier += 0.15
                
                # Calculate final score
                scan.threat_score = min(100, int(base_score * multiplier))
                
                # Determine threat level based on score
                if scan.threat_score >= 80:
                    scan.threat_level = 'critical'
                elif scan.threat_score >= 60:
                    scan.threat_level = 'high'
                elif scan.threat_score >= 35:
                    scan.threat_level = 'medium'
                elif scan.threat_score >= 15:
                    scan.threat_level = 'low'
                else:
                    scan.threat_level = 'safe'
                
                # Store comprehensive static analysis data (MobSF-style)
                scan.static_analysis = _enrich_static_analysis(
                    results=results,
                    scan=scan,
                )

            # Run dynamic analysis if enabled
            if scan.dynamic_analysis_enabled:
                # Check if cancelled before dynamic analysis
                if is_cancelled(scan_id):
                    print(f"[ANALYSIS] Scan {scan_id} was cancelled before dynamic analysis")
                    clear_cancellation(scan_id)
                    return False
                
                step_time = time.time()
                try:
                    dynamic_analyzer = DynamicAnalyzer(
                        apk_path=apk_path,
                        package_name=scan.package_name or manifest_data.get('package', ''),
                        cancel_check=lambda: is_cancelled(scan_id),
                    )
                    print("[ANALYSIS] Dynamic analysis started")
                    dynamic_results = dynamic_analyzer.analyze()
                    print(f"[ANALYSIS] Dynamic analysis completed in {time.time() - step_time:.2f}s")
                except Exception as dynamic_error:
                    dynamic_results = {
                        'success': False,
                        'error': str(dynamic_error)
                    }
                    print(f"[ANALYSIS] Dynamic analysis failed: {str(dynamic_error)}")

                results['dynamic_analysis'] = dynamic_results
                scan.dynamic_analysis = dynamic_results

                if dynamic_results.get('cancelled') or is_cancelled(scan_id):
                    print(f"[ANALYSIS] Scan {scan_id} was cancelled during dynamic analysis")
                    clear_cancellation(scan_id)
                    scan.status = 'failed'
                    scan.error_message = 'Analysis cancelled by user'
                    scan.completed_at = timezone.now()
                    scan.save()
                    return False
            
            # Run API fuzzing if enabled
            if scan.fuzzing_enabled:
                # Check if cancelled before fuzzing
                if is_cancelled(scan_id):
                    print(f"[ANALYSIS] Scan {scan_id} was cancelled before fuzzing")
                    clear_cancellation(scan_id)
                    return False
                
                step_time = time.time()
                try:
                    # Extract Android components from static analysis result
                    scan_data = {
                        'static_analysis': scan.static_analysis,
                        'manifest': results.get('manifest', {}),
                    }
                    components = extract_components_for_fuzzing(scan_data)

                    total_components = sum(len(v) for v in components.values())
                    print(f"[ANALYSIS] Starting Android component fuzzing: {total_components} components")

                    # Initialize and run fuzzer
                    from django.conf import settings as dj_settings

                    fuzzer = APKFuzzer(
                        apk_path=apk_path,
                        package_name=scan.package_name or manifest_data.get('package', ''),
                        components=components,
                        device_serial=__import__('os').environ.get('ADB_DEVICE_SERIAL'),
                        timeout=30,
                        max_workers=4,
                        enabled=True,
                        cancel_check=lambda: is_cancelled(scan_id),
                        max_duration=None,
                    )
                    fuzzing_results = fuzzer.fuzz()
                    
                    # Process fuzzing vulnerabilities
                    # If the fuzzer signalled cancellation, stop processing
                    if fuzzing_results.get('cancelled') or is_cancelled(scan_id):
                        print(f"[ANALYSIS] Fuzzing was cancelled for scan {scan_id}")
                        clear_cancellation(scan_id)
                        scan.status = 'failed'
                        scan.error_message = 'Analysis cancelled by user'
                        scan.completed_at = timezone.now()
                        scan.save()
                        return False
                    fuzzing_vulns = fuzzing_results.get('vulnerabilities', [])
                    if fuzzing_vulns:
                        print(f"[ANALYSIS] Fuzzing found {len(fuzzing_vulns)} vulnerabilities")
                        enriched_fuzzing_vulns = [
                            enrich_finding_for_reporting(vuln, origin='fuzzing')
                            for vuln in fuzzing_vulns
                        ]
                        fuzzing_results['vulnerabilities'] = enriched_fuzzing_vulns
                        fuzzing_results['source_breakdown'] = fuzzing_results.get('source_breakdown', {})
                        fuzzing_results['source_breakdown']['fuzzing'] = len(enriched_fuzzing_vulns)
                        # Add fuzzing vulnerabilities to main vulnerability list
                        all_vulnerabilities.extend(enriched_fuzzing_vulns)
                        results['vulnerabilities'] = all_vulnerabilities
                        
                        # Update vulnerability counts
                        for vuln in enriched_fuzzing_vulns:
                            sev = vuln.get('severity', 'info').lower()
                            if sev == 'critical':
                                scan.critical_issues += 1
                            elif sev == 'high':
                                scan.high_issues += 1
                            elif sev == 'medium':
                                scan.medium_issues += 1
                            elif sev == 'low':
                                scan.low_issues += 1
                        
                        scan.total_issues = len(all_vulnerabilities)
                        
                        # Recalculate threat score
                        weighted_score = 0.0
                        for vuln in all_vulnerabilities:
                            sev = vuln.get('severity', 'info').lower()
                            source = (vuln.get('analysis_origin') or vuln.get('origin') or vuln.get('source') or 'unknown').lower()
                            severity_weight = FINDING_SEVERITY_WEIGHTS.get(sev, 1)
                            source_weight = FINDING_SOURCE_WEIGHTS.get(source, FINDING_SOURCE_WEIGHTS['unknown'])
                            weighted_score += severity_weight * source_weight
                        scan.threat_score = min(100, int(round(weighted_score)))
                        
                        # Update threat level
                        if scan.threat_score >= 80:
                            scan.threat_level = 'critical'
                        elif scan.threat_score >= 60:
                            scan.threat_level = 'high'
                        elif scan.threat_score >= 35:
                            scan.threat_level = 'medium'
                        elif scan.threat_score >= 15:
                            scan.threat_level = 'low'
                    
                    print(f"[ANALYSIS] Fuzzing completed in {time.time() - step_time:.2f}s")
                    
                except Exception as fuzzing_error:
                    fuzzing_results = {
                        'enabled': True,
                        'success': False,
                        'error': str(fuzzing_error)
                    }
                    print(f"[ANALYSIS] Fuzzing failed: {str(fuzzing_error)}")
                
                results['fuzzing_analysis'] = fuzzing_results
                scan.fuzzing_analysis = fuzzing_results
            
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            
            try:
                scan.save()
            except IntegrityError as integrity_error:
                # Handle duplicate scan constraint (user_id, hash_md5 must be unique)
                print(f"[ANALYSIS] IntegrityError during save: {str(integrity_error)}")
                print(f"[ANALYSIS] Attempting to update existing scan with same hash...")
                
                # Find and update the existing scan for this user
                try:
                    existing_scan = Scan.objects.filter(
                        user=scan.user,
                        hash_md5=scan.hash_md5
                    ).exclude(id=scan.id).first()
                    
                    if existing_scan:
                        # Update existing scan with new analysis results
                        existing_scan.status = scan.status
                        existing_scan.completed_at = scan.completed_at
                        existing_scan.threat_level = scan.threat_level
                        existing_scan.threat_score = scan.threat_score
                        existing_scan.total_issues = scan.total_issues
                        existing_scan.critical_issues = scan.critical_issues
                        existing_scan.high_issues = scan.high_issues
                        existing_scan.medium_issues = scan.medium_issues
                        existing_scan.low_issues = scan.low_issues
                        existing_scan.static_analysis = scan.static_analysis
                        existing_scan.dynamic_analysis = scan.dynamic_analysis
                        existing_scan.fuzzing_enabled  = scan.fuzzing_enabled
                        existing_scan.fuzzing_analysis = scan.fuzzing_analysis
                        existing_scan.save()
                        
                        # Delete the duplicate scan and use existing one
                        scan.delete()
                        scan = existing_scan
                        print(f"[ANALYSIS] Successfully updated existing scan {scan.id}")
                    else:
                        # Shouldn't happen, but log it
                        print(f"[ANALYSIS] Could not find existing scan to update")
                        raise
                except Exception as update_error:
                    print(f"[ANALYSIS] Failed to update existing scan: {str(update_error)}")
                    raise
            
            # Create vulnerabilities
            for vuln in all_vulnerabilities:
                Vulnerability.objects.create(
                    scan=scan,
                    title=vuln.get('title', 'Unknown Vulnerability'),
                    description=vuln.get('description', ''),
                    severity=vuln.get('severity', 'info'),
                    category=vuln.get('category', 'Other'),
                    file_path=vuln.get('file_path', ''),
                    line_number=vuln.get('line_number'),
                    remediation=vuln.get('remediation', '')
                )
            
            # Create permissions
            for perm in results.get('permissions', []):
                # Handle both string and dict formats
                if isinstance(perm, str):
                    perm_name = perm
                    is_dangerous = _is_dangerous_permission(perm_name)
                    description = _get_permission_description(perm_name)
                else:
                    perm_name = perm.get('permission_name', '')
                    is_dangerous = perm.get('is_dangerous', False)
                    description = perm.get('description', '')
                
                Permission.objects.create(
                    scan=scan,
                    permission_name=perm_name,
                    is_dangerous=is_dangerous,
                    description=description
                )
            
            # Generate and save report
            text_report = ReportGenerator.generate_text_report(results)
            json_report = ReportGenerator.generate_json_report(results)

            # Run AI analysis if user opted in
            if getattr(scan, 'ai_analysis_enabled', True):
                try:
                    from .ai_analyzer import generate_ai_report
                    ai_step_time = time.time()
                    print(f"[ANALYSIS] Running AI security intelligence for scan {scan_id}...")
                    ai_result = generate_ai_report(scan)
                    scan.ai_report = ai_result
                    scan.save(update_fields=['ai_report'])
                    print(f"[ANALYSIS] AI analysis completed in {time.time() - ai_step_time:.2f}s")
                except Exception as ai_err:
                    print(f"[ANALYSIS] AI analysis skipped: {str(ai_err)}")
            else:
                print(f"[ANALYSIS] AI analysis disabled by user for scan {scan_id}, skipping")

            # Check if cancelled before PDF generation
            if is_cancelled(scan_id):
                print(f"[ANALYSIS] Scan {scan_id} was cancelled before report generation")
                clear_cancellation(scan_id)
                return False
            
            # Generate PDF report
            step_time = time.time()
            pdf_generator = PDFReportGenerator()
            
            # Prepare scan data for PDF
            scan_dict = {
                'id': scan.id,
                'app_name': scan.app_name,
                'package_name': scan.package_name,
                'version_name': scan.version or 'Unknown',
                'version_code': scan.version or 'Unknown',
                'threat_level': scan.threat_level,
                'threat_score': scan.threat_score,
                'critical_issues': scan.critical_issues,
                'high_issues': scan.high_issues,
                'medium_issues': scan.medium_issues,
                'low_issues': scan.low_issues,
            }
            
            # Get permissions data
            permissions_data = results.get('permissions', [])
            
            try:
                pdf_filename = pdf_generator.generate(
                    scan_data=scan_dict,
                    vulnerabilities=all_vulnerabilities,
                    permissions=permissions_data,
                    static_analysis=scan.static_analysis,
                    dynamic_analysis=scan.dynamic_analysis or results.get('dynamic_analysis', {}),
                    ai_report=scan.ai_report or None
                )
                print(f"[ANALYSIS] PDF report generated in {time.time() - step_time:.2f}s: {pdf_filename}")
                pdf_url = f"reports/{pdf_filename}"
            except Exception as pdf_error:
                print(f"[ANALYSIS] PDF generation failed: {str(pdf_error)}")
                import traceback
                traceback.print_exc()
                pdf_url = None
            
            # Create report (pdf_url can be None if PDF generation failed)
            report_data = {
                'scan': scan,
                'summary': text_report,
                'recommendations': _generate_recommendations(results),
                'json_url': json_report,  # In production, save to file storage
            }
            if pdf_url:
                report_data['pdf_url'] = pdf_url
            
            Report.objects.create(**report_data)
            
            print(f"[ANALYSIS] Report generated successfully")
            return True
            
        else:
            scan.status = 'failed'
            scan.save()
            print(f"[ANALYSIS] Analysis failed: {results.get('error')}")
            return False
            
    except Exception as e:
        print(f"[ANALYSIS] ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        try:
            scan = Scan.objects.get(id=scan_id)
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.save()
        except:
            pass
        return False
    finally:
        # Always clear cancellation flag when analysis ends
        clear_cancellation(scan_id)
        total_time = time.time() - start_time
        print(f"[ANALYSIS] Total analysis time: {total_time:.2f}s")


def _generate_recommendations(results: Dict) -> str:
    """Generate security recommendations based on findings"""
    recommendations = []
    
    vulnerabilities = results.get('vulnerabilities', [])
    
    # Count by category
    categories = {}
    for vuln in vulnerabilities:
        cat = vuln.get('category', 'Other')
        categories[cat] = categories.get(cat, 0) + 1
    
    recommendations.append("SECURITY RECOMMENDATIONS")
    recommendations.append("=" * 60)
    recommendations.append("")
    
    if categories.get('Secrets', 0) > 0:
        recommendations.append("1. Secure Secret Management")
        recommendations.append("   - Move hardcoded credentials to secure storage")
        recommendations.append("   - Use Android Keystore for sensitive keys")
        recommendations.append("   - Implement environment-based configuration")
        recommendations.append("")
    
    if categories.get('Cryptography', 0) > 0:
        recommendations.append("2. Strengthen Cryptography")
        recommendations.append("   - Replace weak algorithms (DES, MD5) with AES-256, SHA-256")
        recommendations.append("   - Use authenticated encryption (GCM mode)")
        recommendations.append("   - Implement proper key derivation (PBKDF2, Argon2)")
        recommendations.append("")
    
    if categories.get('Storage', 0) > 0:
        recommendations.append("3. Secure Data Storage")
        recommendations.append("   - Encrypt local databases with SQLCipher")
        recommendations.append("   - Use MODE_PRIVATE for file creation")
        recommendations.append("   - Implement secure SharedPreferences")
        recommendations.append("")
    
    if categories.get('Network', 0) > 0:
        recommendations.append("4. Network Security")
        recommendations.append("   - Enforce HTTPS-only connections")
        recommendations.append("   - Implement certificate pinning")
        recommendations.append("   - Use Network Security Configuration")
        recommendations.append("")
    
    if categories.get('WebView', 0) > 0:
        recommendations.append("5. WebView Security")
        recommendations.append("   - Disable JavaScript if not required")
        recommendations.append("   - Disable file access in WebView")
        recommendations.append("   - Implement Content Security Policy")
        recommendations.append("")
    
    recommendations.append("6. General Best Practices")
    recommendations.append("   - Disable debugging in production builds")
    recommendations.append("   - Implement code obfuscation (ProGuard/R8)")
    recommendations.append("   - Regular security audits and updates")
    recommendations.append("   - Follow OWASP Mobile Top 10 guidelines")
    
    return "\n".join(recommendations)


def _filter_vulnerabilities(vulnerabilities):
    """Normalize, de-duplicate, and sort vulnerabilities in a MobSF-like manner."""
    if not vulnerabilities:
        return []

    severity_rank = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1,
    }

    deduped = {}

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue

        title = (vuln.get('title') or 'Unknown Vulnerability').strip()
        category = (vuln.get('category') or 'Other').strip()
        severity = (vuln.get('severity') or 'info').lower().strip()
        if severity not in severity_rank:
            severity = 'info'

        file_path = (vuln.get('file_path') or '').strip()
        line_number = vuln.get('line_number')

        key = (title.lower(), category.lower(), file_path.lower(), str(line_number or ''))
        existing = deduped.get(key)

        normalized = {
            'title': title,
            'description': (vuln.get('description') or '').strip(),
            'severity': severity,
            'category': category,
            'file_path': file_path,
            'line_number': line_number,
            'remediation': (vuln.get('remediation') or '').strip(),
        }

        if not existing:
            deduped[key] = normalized
            continue

        if severity_rank.get(normalized['severity'], 1) > severity_rank.get(existing['severity'], 1):
            deduped[key] = normalized

    sorted_vulns = sorted(
        deduped.values(),
        key=lambda v: (-severity_rank.get(v.get('severity', 'info'), 1), v.get('category', ''), v.get('title', '')),
    )

    return sorted_vulns


def _enrich_static_analysis(results: Dict, scan: Scan) -> Dict:
    """Merge analysis artifacts into a MobSF-style static analysis payload."""
    static_analysis = results.get('static_analysis', {}) or {}

    static_analysis['app_info'] = {
        'app_name': scan.app_name,
        'package_name': scan.package_name,
        'version': scan.version,
        'file_name': scan.file_name,
        'file_size': scan.file_size,
        'hash_md5': scan.hash_md5,
        'hash_sha256': scan.hash_sha256,
    }

    static_analysis['manifest'] = results.get('manifest', {})
    static_analysis['certificate'] = results.get('certificate', {})
    static_analysis['permissions'] = results.get('permissions', [])
    static_analysis['components'] = results.get('components', {})
    static_analysis['code_analysis'] = results.get('code_analysis', {})
    static_analysis['security_checks'] = results.get('security_checks', {})
    static_analysis['decompilation'] = results.get('decompilation', {})
    static_analysis['unpacking'] = results.get('unpacking', {})

    return static_analysis


def _is_dangerous_permission(perm_name: str) -> bool:
    """Check if permission is dangerous"""
    dangerous = [
        'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_SMS', 'SEND_SMS',
        'RECEIVE_SMS', 'READ_CALL_LOG', 'WRITE_CALL_LOG', 'CAMERA',
        'RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
        'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'CALL_PHONE',
        'READ_PHONE_STATE', 'GET_ACCOUNTS', 'READ_PHONE_NUMBERS'
    ]
    return any(d in perm_name for d in dangerous)


def _get_permission_description(perm_name: str) -> str:
    """Get permission description"""
    descriptions = {
        'INTERNET': 'Allows network access',
        'ACCESS_NETWORK_STATE': 'View network connections',
        'CAMERA': 'Access device camera',
        'RECORD_AUDIO': 'Record audio',
        'READ_CONTACTS': 'Read contacts',
        'WRITE_CONTACTS': 'Modify contacts',
        'READ_SMS': 'Read SMS messages',
        'SEND_SMS': 'Send SMS messages',
        'ACCESS_FINE_LOCATION': 'Access precise location',
        'ACCESS_COARSE_LOCATION': 'Access approximate location',
        'READ_EXTERNAL_STORAGE': 'Read from external storage',
        'WRITE_EXTERNAL_STORAGE': 'Write to external storage',
        'CALL_PHONE': 'Make phone calls',
        'READ_PHONE_STATE': 'Read phone state',
        'VIBRATE': 'Control vibration',
        'WAKE_LOCK': 'Prevent device from sleeping',
    }
    
    for key, desc in descriptions.items():
        if key in perm_name:
            return desc
    
    return 'Permission details not available'
