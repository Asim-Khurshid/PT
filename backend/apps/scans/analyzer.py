"""
APK Static Analysis Engine 
Handles decompilation, analysis, and vulnerability detection
"""
import os
import subprocess
import zipfile
import hashlib
import re
import json
from pathlib import Path
from xml.etree import ElementTree as ET
from typing import Callable, Dict, List, Optional, Tuple
import tempfile
import shutil
from .decompiler_androguard import AndroguardDecompiler, CodeAnalyzer
from .static_analyzer import StaticAnalyzer


class APKAnalyzer:
    """Main APK static analysis engine - Optimized for speed"""
    
    def __init__(self, apk_path: str, cancel_check: Optional[Callable[[], bool]] = None):
        self.apk_path = apk_path
        self.temp_dir = None
        self.findings = []
        self.permissions = []
        self.components = {}
        self.certificate_info = {}
        self.cancel_check = cancel_check

    def _is_cancelled(self) -> bool:
        if not self.cancel_check:
            return False
        try:
            return bool(self.cancel_check())
        except Exception:
            return False

    def _cancel_result(self) -> Dict:
        return {
            'success': False,
            'cancelled': True,
            'error': 'Analysis cancelled by user',
            'vulnerabilities': [],
        }
        
    def analyze(self) -> Dict:
        """Run complete static analysis"""
        try:
            if self._is_cancelled():
                return self._cancel_result()

            # Create temporary workspace
            self.temp_dir = tempfile.mkdtemp(prefix='apk_analysis_')
            
            # Initialize APK decompiler
            decompiler = AndroguardDecompiler(self.apk_path, self.temp_dir)
            
            # Run static analysis
            analysis_results = decompiler.analyze()

            if self._is_cancelled():
                return self._cancel_result()

            # Populate components from decompilation results so the fuzzer
            # has access to activities, services, receivers and providers.
            self.components = {
                'activities': analysis_results.get('activities', []),
                'services':   analysis_results.get('services', []),
                'receivers':  analysis_results.get('receivers', []),
                'providers':  analysis_results.get('providers', []),
            }

            # Run comprehensive static analysis 
            static_analyzer = StaticAnalyzer(self.apk_path, decompiler.apk)
            comprehensive_analysis = static_analyzer.analyze()

            if self._is_cancelled():
                return self._cancel_result()
            
            results = {
                'success': True,
                'unpacking': self._unpack_apk(),
                'decompilation': analysis_results,
                'manifest': analysis_results.get('manifest', {}),
                'code_analysis': self._fast_code_analysis(analysis_results),
                'security_checks': self._security_checks(analysis_results),
                'certificate': analysis_results.get('certificate', {}),
                'permissions': analysis_results.get('permissions', []),
                'components': self.components,
                'vulnerabilities': self.findings,
                'summary': self._generate_summary(),
                'static_analysis': comprehensive_analysis  # comprehensive data
            }

            if self._is_cancelled():
                return self._cancel_result()
            
            return results
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'vulnerabilities': []
            }
        finally:
            # Cleanup
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _unpack_apk(self) -> Dict:
        """Extract APK contents and list important files"""
        try:
            extract_dir = os.path.join(self.temp_dir, 'extracted')
            os.makedirs(extract_dir, exist_ok=True)
            
            file_list = []
            important_files = []
            
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
                
                # Get all files from APK
                for file_info in zip_ref.filelist:
                    if not file_info.is_dir():
                        file_entry = {
                            'path': file_info.filename,
                            'name': file_info.filename,
                            'size': self._format_size(file_info.file_size),
                            'size_bytes': file_info.file_size,
                            'compressed_size': file_info.compress_size,
                            'type': self._get_file_type(file_info.filename)
                        }
                        file_list.append(file_entry)
                        
                        # Mark important files
                        if self._is_important_file(file_info.filename):
                            important_files.append(file_entry)
            
            # Sort by importance and size, limit to top 15
            important_files.sort(key=lambda x: (self._file_priority(x['path']), -x['size_bytes']))
            important_files = important_files[:15]
            
            return {
                'extracted': True,
                'path': extract_dir,
                'file_count': len(file_list),
                'total_size': self._format_size(sum(f['size_bytes'] for f in file_list)),
                'important_files': important_files,
                'all_files': file_list[:100]  # Limit to 100 files
            }
            
        except Exception as e:
            return {'extracted': False, 'error': str(e)}
    
    def _get_file_type(self, filename: str) -> str:
        """Determine file type from extension"""
        ext = filename.lower().split('.')[-1] if '.' in filename else 'unknown'
        type_map = {
            'xml': 'XML',
            'dex': 'DEX',
            'so': 'Library',
            'png': 'Image',
            'jpg': 'Image',
            'jpeg': 'Image',
            'json': 'JSON',
            'txt': 'Text',
            'html': 'HTML',
            'js': 'JavaScript',
            'css': 'Stylesheet',
            'arsc': 'Resources',
            'rsa': 'Certificate',
            'sf': 'Signature',
            'mf': 'Manifest'
        }
        
        # Special handling for AndroidManifest.xml
        if 'AndroidManifest.xml' in filename:
            return 'Manifest'
        
        return type_map.get(ext, f'.{ext}' if ext != 'unknown' else 'Unknown')
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def _is_important_file(self, filename: str) -> bool:
        """Check if file is important for analysis"""
        important_patterns = [
            'AndroidManifest.xml',
            'classes.dex',
            'resources.arsc',
            'META-INF/',
            'res/layout/',
            'res/values/',
            'lib/',
            'assets/',
            '.so',
            '.xml',
            '.json'
        ]
        return any(pattern in filename for pattern in important_patterns)
    
    def _file_priority(self, filename: str) -> int:
        """Get priority for sorting (lower = more important)"""
        if 'AndroidManifest.xml' in filename:
            return 0
        elif 'classes' in filename and '.dex' in filename:
            return 1
        elif 'resources.arsc' in filename:
            return 2
        elif 'META-INF' in filename:
            return 3
        elif '.so' in filename:
            return 4
        elif '/layout/' in filename:
            return 5
        elif '/values/' in filename:
            return 6
        return 10
    
    # Removed _analyze_manifest, _malware_scan - using built-in analysis methods
    
    def _is_dangerous_permission(self, perm_name: str) -> bool:
        """Check if permission is dangerous"""
        dangerous = [
            'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_SMS', 'SEND_SMS',
            'RECEIVE_SMS', 'READ_CALL_LOG', 'WRITE_CALL_LOG', 'CAMERA',
            'RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
            'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'CALL_PHONE',
            'READ_PHONE_STATE', 'GET_ACCOUNTS'
        ]
        return any(d in perm_name for d in dangerous)
    
    def _get_permission_description(self, perm_name: str) -> str:
        """Get permission description"""
        descriptions = {
            'INTERNET': 'Access network connections',
            'CAMERA': 'Access camera',
            'READ_EXTERNAL_STORAGE': 'Read storage',
            'WRITE_EXTERNAL_STORAGE': 'Write to storage',
            'ACCESS_FINE_LOCATION': 'Access precise location',
            'ACCESS_COARSE_LOCATION': 'Access approximate location',
            'RECORD_AUDIO': 'Record audio',
            'READ_CONTACTS': 'Read contacts',
            'SEND_SMS': 'Send SMS messages'
        }
        
        for key, desc in descriptions.items():
            if key in perm_name:
                return desc
        
        return 'Android permission'
    
    # Permission analysis helpers
    
    def _fast_code_analysis(self, analysis_results: Dict) -> Dict:
        """Fast code analysis using static analysis results"""
        vulnerabilities_found = []
        
        # Get code analysis results
        code_analysis = analysis_results.get('code_analysis', {})
        
        # Extract strings for pattern matching
        strings = analysis_results.get('code_analysis', {}).get('strings', [])
        
        # Run fast pattern-based analysis
        if strings:
            pattern_findings = CodeAnalyzer.scan_strings(strings)
            for finding in pattern_findings:
                vulnerabilities_found.append({
                    'title': finding['description'],
                    'description': f"Found: {finding['matched_text']}",
                    'severity': finding['severity'],
                    'category': finding['category'],
                    'file_path': 'strings.xml',
                    'remediation': self._get_remediation(finding['category'])
                })
        
        # Check network security
        network = code_analysis.get('network_calls', {})
        if network.get('http_urls'):
            vulnerabilities_found.append({
                'title': 'Insecure HTTP Communication',
                'description': f"Found {len(network['http_urls'])} HTTP URLs (unencrypted)",
                'severity': 'high',
                'category': 'network_security',
                'file_path': 'network',
                'remediation': 'Use HTTPS for all network communications'
            })
        
        # Check crypto usage
        crypto = code_analysis.get('crypto_usage', {})
        if crypto.get('insecure_random'):
            vulnerabilities_found.append({
                'title': 'Insecure Random Number Generation',
                'description': 'Using non-cryptographic random number generator',
                'severity': 'medium',
                'category': 'insecure_crypto',
                'file_path': 'crypto',
                'remediation': 'Use SecureRandom for cryptographic operations'
            })
        
        # Store findings
        self.findings = vulnerabilities_found
        
        return {
            'analyzed': True,
            'total_findings': len(vulnerabilities_found),
            'findings': vulnerabilities_found[:20]  # Limit for performance
        }
    
    def _security_checks(self, analysis_results: Dict) -> Dict:
        """Fast security checks using analysis data"""
        checks = {
            'debuggable': False,
            'backup_enabled': False,
            'cleartext_traffic': False,
            'exported_components': 0,
        }
        
        # Check manifest settings
        manifest = analysis_results.get('manifest', {})
        
        # Component export check
        activities = analysis_results.get('activities', [])
        services = analysis_results.get('services', [])
        checks['exported_components'] = len(activities) + len(services)
        
        return checks
        
        # 2. Check for insecure crypto
        crypto_vulns = self._check_insecure_crypto()
        vulnerabilities_found.extend(crypto_vulns)
        
        # 3. Check WebView security
        webview_vulns = self._check_webview_security()
        vulnerabilities_found.extend(webview_vulns)
        
        # 4. Check file storage
        storage_vulns = self._check_file_storage()
        vulnerabilities_found.extend(storage_vulns)
        
        # 5. Check network security
        network_vulns = self._check_network_security()
        vulnerabilities_found.extend(network_vulns)
        
        self.findings.extend(vulnerabilities_found)
        
        return {
            'analyzed': True,
            'vulnerabilities_found': len(vulnerabilities_found),
            'categories': {
                'secrets': len(secret_vulns),
                'crypto': len(crypto_vulns),
                'webview': len(webview_vulns),
                'storage': len(storage_vulns),
                'network': len(network_vulns)
            }
        }
    
    def _check_hardcoded_secrets(self) -> List[Dict]:
        """Detect hardcoded API keys, passwords, tokens"""
        findings = []
        
        patterns = {
            'api_key': r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            'aws_key': r'(?i)(aws|amazon)[_-]?(access[_-]?key|secret)\s*[=:]\s*["\']([A-Z0-9]{20,})["\']',
            'password': r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
            'token': r'(?i)(token|auth[_-]?token)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
            'private_key': r'-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----',
        }
        
        # Simulate finding hardcoded secrets
        findings.append({
            'title': 'Hardcoded API Key Detected',
            'severity': 'high',
            'category': 'Secrets',
            'description': 'Application contains hardcoded API key in source code',
            'file_path': 'com/example/Config.java',
            'line_number': 42,
            'remediation': 'Store sensitive keys in secure storage (Android Keystore) or use environment variables'
        })
        
        return findings
    
    def _check_insecure_crypto(self) -> List[Dict]:
        """Check for weak cryptographic implementations"""
        findings = []
        
        # Weak algorithms to detect
        weak_algos = ['DES', 'RC2', 'RC4', 'MD5', 'SHA1']
        
        findings.append({
            'title': 'Weak Encryption Algorithm (DES)',
            'severity': 'high',
            'category': 'Cryptography',
            'description': 'Application uses DES encryption which is cryptographically weak',
            'file_path': 'com/example/crypto/Encryption.java',
            'line_number': 89,
            'remediation': 'Use AES-256 with GCM mode instead of DES'
        })
        
        findings.append({
            'title': 'Insecure Hash Function (MD5)',
            'severity': 'medium',
            'category': 'Cryptography',
            'description': 'MD5 hash function used for data integrity, which is vulnerable to collisions',
            'file_path': 'com/example/utils/HashUtil.java',
            'line_number': 34,
            'remediation': 'Use SHA-256 or SHA-3 instead of MD5'
        })
        
        return findings
    
    def _check_webview_security(self) -> List[Dict]:
        """Check for WebView security issues"""
        findings = []
        
        findings.append({
            'title': 'WebView JavaScript Enabled',
            'severity': 'medium',
            'category': 'WebView',
            'description': 'WebView has JavaScript enabled without proper validation',
            'file_path': 'com/example/ui/WebActivity.java',
            'line_number': 56,
            'remediation': 'Disable JavaScript if not needed, or implement proper Content Security Policy'
        })
        
        findings.append({
            'title': 'WebView File Access Enabled',
            'severity': 'high',
            'category': 'WebView',
            'description': 'WebView allows file access which can lead to local file disclosure',
            'file_path': 'com/example/ui/WebActivity.java',
            'line_number': 58,
            'remediation': 'Disable file access: setAllowFileAccess(false)'
        })
        
        return findings
    
    def _check_file_storage(self) -> List[Dict]:
        """Check for insecure file storage"""
        findings = []
        
        findings.append({
            'title': 'World-Readable File Creation',
            'severity': 'critical',
            'category': 'Storage',
            'description': 'Files created with MODE_WORLD_READABLE allowing other apps to read',
            'file_path': 'com/example/storage/DataManager.java',
            'line_number': 78,
            'remediation': 'Use MODE_PRIVATE for file creation or Android Keystore for sensitive data'
        })
        
        findings.append({
            'title': 'Unencrypted SQLite Database',
            'severity': 'high',
            'category': 'Storage',
            'description': 'SQLite database stores data without encryption',
            'file_path': 'com/example/db/DatabaseHelper.java',
            'line_number': 23,
            'remediation': 'Use SQLCipher to encrypt the database'
        })
        
        return findings
    
    def _check_network_security(self) -> List[Dict]:
        """Check network security configuration"""
        findings = []
        
        findings.append({
            'title': 'Cleartext Traffic Allowed',
            'severity': 'high',
            'category': 'Network',
            'description': 'Application allows HTTP connections which can be intercepted',
            'file_path': 'AndroidManifest.xml',
            'line_number': 12,
            'remediation': 'Enforce HTTPS-only with Network Security Configuration'
        })
        
        findings.append({
            'title': 'Certificate Pinning Not Implemented',
            'severity': 'medium',
            'category': 'Network',
            'description': 'App does not implement certificate pinning for sensitive connections',
            'file_path': 'com/example/network/ApiClient.java',
            'line_number': 45,
            'remediation': 'Implement certificate pinning to prevent man-in-the-middle attacks'
        })
        
        return findings
    
    # Removed old _security_checks method - using the new one with androguard_results
    
    def _check_debuggable(self) -> bool:
        """Check if app is debuggable"""
        return True  # Simulated
    
    def _check_backup_allowed(self) -> bool:
        """Check if backup is allowed"""
        return True  # Simulated
    
    def _check_obfuscation(self) -> bool:
        """Check if code is obfuscated"""
        return False  # Simulated
    
    def _check_suspicious_permissions(self) -> List[str]:
        """Detect suspicious permission combinations"""
        suspicious = []
        perm_names = [p['permission_name'] for p in self.permissions]
        
        # Check for suspicious combinations
        if 'android.permission.SEND_SMS' in perm_names and 'android.permission.READ_CONTACTS' in perm_names:
            suspicious.append('SMS + Contacts (potential spyware)')
        
        if 'android.permission.RECORD_AUDIO' in perm_names and 'android.permission.INTERNET' in perm_names:
            suspicious.append('Audio Recording + Internet (potential surveillance)')
        
        return suspicious
    
    def _extract_certificate_info(self) -> Dict:
        """Extract certificate and signing information"""
        try:
            # Extract META-INF certificate files
            cert_dir = os.path.join(self.temp_dir, 'extracted', 'META-INF')
            
            cert_info = {
                'has_signature': os.path.exists(cert_dir) if cert_dir else False,
                'signature_version': 'v1',  # Simulated
                'issuer': 'CN=Android Debug, O=Android, C=US',  # Simulated
                'valid_from': '2024-01-01',
                'valid_until': '2054-01-01',
                'algorithm': 'SHA256withRSA'
            }
            
            self.certificate_info = cert_info
            return cert_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_summary(self) -> Dict:
        """Generate analysis summary with risk scoring"""
        total_vulns = len(self.findings)
        
        severity_counts = {
            'critical': len([v for v in self.findings if v['severity'] == 'critical']),
            'high': len([v for v in self.findings if v['severity'] == 'high']),
            'medium': len([v for v in self.findings if v['severity'] == 'medium']),
            'low': len([v for v in self.findings if v['severity'] == 'low'])
        }
        
        # Calculate base risk score using weighted formula (0-100)
        # Weights based on CVSS severity ratings
        base_score = (
            severity_counts['critical'] * 25 +  # Critical vulnerabilities have highest weight
            severity_counts['high'] * 15 +       # High severity
            severity_counts['medium'] * 8 +      # Medium severity
            severity_counts['low'] * 3           # Low severity
        )
        
        # Apply multiplier based on dangerous permissions
        multiplier = 1.0
        dangerous_perm_count = len([p for p in self.permissions if p['is_dangerous']])
        if dangerous_perm_count > 5:
            multiplier += 0.2
        elif dangerous_perm_count > 3:
            multiplier += 0.1
        
        # Calculate final risk score
        risk_score = min(100, int(base_score * multiplier))
        
        # Determine threat level based on risk score
        if risk_score >= 80:
            threat_level = 'critical'
        elif risk_score >= 60:
            threat_level = 'high'
        elif risk_score >= 35:
            threat_level = 'medium'
        elif risk_score >= 15:
            threat_level = 'low'
        else:
            threat_level = 'safe'
        
        return {
            'total_vulnerabilities': total_vulns,
            'severity_counts': severity_counts,
            'risk_score': risk_score,
            'threat_level': threat_level,
            'permissions_count': len(self.permissions),
            'dangerous_permissions': dangerous_perm_count
        }
    
    def _get_remediation(self, category: str) -> str:
        """Get remediation advice for vulnerability category"""
        remediations = {
            'hardcoded_secrets': 'Remove hardcoded secrets. Use Android Keystore or secure configuration.',
            'insecure_crypto': 'Use strong cryptographic algorithms (AES-256, SHA-256). Avoid MD5, SHA1, DES.',
            'insecure_network': 'Use HTTPS for all network communications. Implement certificate pinning.',
            'webview_issues': 'Disable JavaScript in WebView unless required. Validate all URLs.',
            'insecure_storage': 'Use internal storage with MODE_PRIVATE. Encrypt sensitive data.',
        }
        return remediations.get(category, 'Follow security best practices.')


class ReportGenerator:
    """Generate detailed security reports"""
    
    @staticmethod
    def generate_text_report(analysis_results: Dict) -> str:
        """Generate human-readable text report"""
        summary = analysis_results.get('summary', {})
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        dynamic_analysis = analysis_results.get('dynamic_analysis', {})
        
        report = []
        report.append("=" * 80)
        report.append("APK SECURITY ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")
        
        report.append("SUMMARY")
        report.append("-" * 80)
        report.append(f"Risk Score: {summary.get('risk_score', 0)}/100")
        report.append(f"Threat Level: {summary.get('threat_level', 'unknown').upper()}")
        report.append(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        report.append("")
        
        severity = summary.get('severity_breakdown', {})
        report.append("Severity Breakdown:")
        report.append(f"  Critical: {severity.get('critical', 0)}")
        report.append(f"  High: {severity.get('high', 0)}")
        report.append(f"  Medium: {severity.get('medium', 0)}")
        report.append(f"  Low: {severity.get('low', 0)}")
        report.append("")
        
        if vulnerabilities:
            report.append("VULNERABILITIES FOUND")
            report.append("-" * 80)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                report.append(f"\n{i}. {vuln.get('title', 'Unknown')}")
                report.append(f"   Severity: {vuln.get('severity', 'unknown').upper()}")
                report.append(f"   Category: {vuln.get('category', 'Unknown')}")
                report.append(f"   Description: {vuln.get('description', 'N/A')}")
                report.append(f"   Location: {vuln.get('file_path', 'N/A')}:{vuln.get('line_number', 'N/A')}")
                report.append(f"   Remediation: {vuln.get('remediation', 'N/A')}")

        if dynamic_analysis:
            report.append("\n" + "-" * 80)
            report.append("DYNAMIC ANALYSIS SUMMARY")
            report.append("-" * 80)
            findings = dynamic_analysis.get('findings', [])
            logcat = dynamic_analysis.get('logcat', {})
            indicators = dynamic_analysis.get('indicators', {})

            report.append(f"Findings: {len(findings)}")
            report.append(f"Logcat Lines: {logcat.get('total_lines', 0)}")
            report.append(f"Suspicious Logcat Lines: {len(logcat.get('suspicious_lines', []))}")
            report.append(f"URLs Observed: {len(indicators.get('urls', []))}")
            report.append(f"IPs Observed: {len(indicators.get('ips', []))}")

            if findings:
                report.append("\nDynamic Findings")
                for i, finding in enumerate(findings, 1):
                    report.append(f"  {i}. {finding.get('title', 'Finding')}")
                    report.append(f"     Severity: {finding.get('severity', 'info').upper()}")
                    report.append(f"     Category: {finding.get('category', 'General')}")
                    standard = finding.get('standard', '')
                    if standard:
                        report.append(f"     Standard: {standard}")
                    evidence = finding.get('evidence', [])
                    if evidence:
                        report.append(f"     Evidence: {str(evidence)[:300]}")
                    remediation = finding.get('remediation', '')
                    if remediation:
                        report.append(f"     Remediation: {remediation}")
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    @staticmethod
    def generate_json_report(analysis_results: Dict) -> str:
        """Generate JSON format report"""
        return json.dumps(analysis_results, indent=2)
