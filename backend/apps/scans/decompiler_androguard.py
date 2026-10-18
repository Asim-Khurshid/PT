"""
Enhanced APK Decompilation Module using Androguard
Pure Python solution - faster and more integrated than JADX
"""
import os
import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Set
from zipfile import ZipFile

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    from androguard.decompiler.decompiler import DecompilerDAD
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False


class AndroguardDecompiler:
    """
    APK Decompiler using Androguard (Pure Python)
    Faster and more integrated than Java-based tools
    """
    
    def __init__(self, apk_path: str, output_dir: str):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.apk = None
        self.dex_files = []
        
    def analyze(self) -> Dict:
        """Main analysis entry point"""
        if not ANDROGUARD_AVAILABLE:
            return self._fallback_analysis()
        
        try:
            # Load APK
            self.apk = APK(self.apk_path)
            
            results = {
                'success': True,
                'method': 'androguard',
                'manifest': self._extract_manifest(),
                'permissions': self._extract_permissions(),
                'activities': self._extract_activities(),
                'services': self._extract_services(),
                'receivers': self._extract_receivers(),
                'providers': self._extract_providers(),
                'certificate': self._extract_certificate_info(),
                'code_analysis': self._analyze_code(),
                'resources': self._extract_resources(),
            }
            
            return results
            
        except Exception as e:
            return {
                'success': False,
                'method': 'androguard',
                'error': str(e),
                'fallback': self._fallback_analysis()
            }
    
    def _extract_manifest(self) -> Dict:
        """Extract manifest information"""
        try:
            manifest = {
                'package': self.apk.get_package(),
                'version_name': self.apk.get_androidversion_name(),
                'version_code': self.apk.get_androidversion_code(),
                'min_sdk': self.apk.get_min_sdk_version(),
                'target_sdk': self.apk.get_target_sdk_version(),
                'max_sdk': self.apk.get_max_sdk_version(),
            }
            return manifest
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_permissions(self) -> List[str]:
        """Extract requested permissions"""
        try:
            return self.apk.get_permissions()
        except:
            return []
    
    # Android XML namespace for attribute lookup
    _ANDROID_NS = 'http://schemas.android.com/apk/res/android'

    @classmethod
    def _xml_attr(cls, element, name: str):
        """Return the value of an android:name attribute (or None)."""
        return element.get(f'{{{cls._ANDROID_NS}}}{name}')

    def _resolve_name(self, name: str) -> str:
        """Expand a short/relative component name to a fully-qualified one."""
        if not name:
            return name
        package = self.apk.get_package() or ''
        if name.startswith('.'):
            return package + name
        if '.' not in name:
            return package + '.' + name
        return name

    def _parse_components(self, tag: str) -> List[Dict]:
        """
        Parse <activity|service|receiver|provider> elements from the manifest
        and return a list of dicts with name, exported, and permission fields.
        Falls back to a plain string list on any error.
        """
        try:
            xml = self.apk.get_android_manifest_xml()
            app = xml.find('application')
            if app is None:
                raise ValueError('No <application> element')

            result = []
            for el in app.findall(tag):
                name = self._resolve_name(self._xml_attr(el, 'name') or '')
                if not name:
                    continue

                exported_val = self._xml_attr(el, 'exported')
                has_filter   = el.find('intent-filter') is not None
                intent_actions = []
                intent_categories = []
                for intent_filter in el.findall('intent-filter'):
                    for action in intent_filter.findall('action'):
                        action_name = self._xml_attr(action, 'name')
                        if action_name:
                            intent_actions.append(action_name)
                    for category in intent_filter.findall('category'):
                        category_name = self._xml_attr(category, 'name')
                        if category_name:
                            intent_categories.append(category_name)
                if exported_val == 'true':
                    exported = True
                elif exported_val == 'false':
                    exported = False
                else:
                    # Android default: exported if an intent-filter is declared
                    exported = has_filter

                entry: Dict = {
                    'name':       name,
                    'exported':   exported,
                    'permission': self._xml_attr(el, 'permission'),
                    'has_intent_filter': has_filter,
                    'intent_actions': intent_actions,
                    'intent_categories': intent_categories,
                }

                if tag == 'provider':
                    entry['authority']        = self._xml_attr(el, 'authorities') or name
                    entry['readPermission']   = self._xml_attr(el, 'readPermission')
                    entry['writePermission']  = self._xml_attr(el, 'writePermission')
                    entry['grantUriPermissions'] = (
                        (self._xml_attr(el, 'grantUriPermissions') or '').lower() == 'true'
                    )

                result.append(entry)

            return result
        except Exception:
            # Graceful fallback: return plain strings so callers still get data
            fallback_map = {
                'activity': self.apk.get_activities,
                'service':  self.apk.get_services,
                'receiver': self.apk.get_receivers,
                'provider': self.apk.get_providers,
            }
            try:
                return fallback_map[tag]()
            except Exception:
                return []

    def _extract_activities(self) -> List:
        """Extract activities with exported/permission metadata."""
        try:
            return self._parse_components('activity')
        except Exception:
            try:
                return self.apk.get_activities()
            except Exception:
                return []

    def _extract_services(self) -> List:
        """Extract services with exported/permission metadata."""
        try:
            return self._parse_components('service')
        except Exception:
            try:
                return self.apk.get_services()
            except Exception:
                return []

    def _extract_receivers(self) -> List:
        """Extract broadcast receivers with exported/permission metadata."""
        try:
            return self._parse_components('receiver')
        except Exception:
            try:
                return self.apk.get_receivers()
            except Exception:
                return []

    def _extract_providers(self) -> List:
        """Extract content providers with exported/permission/authority metadata."""
        try:
            return self._parse_components('provider')
        except Exception:
            try:
                return self.apk.get_providers()
            except Exception:
                return []
    
    def _extract_certificate_info(self) -> Dict:
        """Extract certificate information"""
        try:
            cert = self.apk.get_certificate_der(self.apk.get_certificates()[0])
            return {
                'issuer': self.apk.get_signature_name(),
                'subject': self.apk.get_signature_name(),
            }
        except:
            return {}
    
    def _analyze_code(self) -> Dict:
        """
        Analyze DEX code for security issues
        Much faster than JADX decompilation
        """
        try:
            analysis = {
                'strings': self._extract_strings(),
                'urls': self._extract_urls(),
                'crypto_usage': self._detect_crypto(),
                'network_calls': self._detect_network(),
                'file_operations': self._detect_file_ops(),
            }
            return analysis
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_strings(self) -> List[str]:
        """Extract strings from DEX"""
        try:
            strings = []
            # Get all strings from APK
            for s in self.apk.get_android_resources_package().get_strings_resources().values():
                if isinstance(s, str) and len(s) > 3:
                    strings.append(s)
            return strings[:500]  # Limit for performance
        except:
            return []
    
    def _extract_urls(self) -> List[str]:
        """Extract URLs from strings"""
        try:
            url_pattern = re.compile(
                r'https?://[^\s<>"{}|\\^`\[\]]+',
                re.IGNORECASE
            )
            
            urls = set()
            for string in self._extract_strings():
                matches = url_pattern.findall(str(string))
                urls.update(matches)
            
            return list(urls)[:100]  # Limit
        except:
            return []
    
    def _detect_crypto(self) -> Dict:
        """Detect cryptographic operations"""
        crypto_indicators = {
            'cipher_usage': False,
            'key_generation': False,
            'ssl_usage': False,
            'insecure_random': False,
        }
        
        try:
            strings = ' '.join(self._extract_strings()).lower()
            
            if 'cipher' in strings or 'encrypt' in strings:
                crypto_indicators['cipher_usage'] = True
            
            if 'keygenerator' in strings or 'keystore' in strings:
                crypto_indicators['key_generation'] = True
            
            if 'ssl' in strings or 'tls' in strings:
                crypto_indicators['ssl_usage'] = True
            
            if 'random' in strings and 'secure' not in strings:
                crypto_indicators['insecure_random'] = True
                
        except:
            pass
        
        return crypto_indicators
    
    def _detect_network(self) -> Dict:
        """Detect network operations"""
        network = {
            'http_urls': [],
            'https_urls': [],
            'ip_addresses': [],
        }
        
        try:
            urls = self._extract_urls()
            
            for url in urls:
                if url.startswith('http://'):
                    network['http_urls'].append(url)
                elif url.startswith('https://'):
                    network['https_urls'].append(url)
            
            # Extract IP addresses
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            strings = ' '.join(self._extract_strings())
            network['ip_addresses'] = list(set(ip_pattern.findall(strings)))[:20]
            
        except:
            pass
        
        return network
    
    def _detect_file_ops(self) -> Dict:
        """Detect file operations"""
        file_ops = {
            'external_storage': False,
            'shared_preferences': False,
            'database_usage': False,
        }
        
        try:
            strings = ' '.join(self._extract_strings()).lower()
            
            if 'external' in strings or 'sdcard' in strings:
                file_ops['external_storage'] = True
            
            if 'sharedpreferences' in strings or 'preferences' in strings:
                file_ops['shared_preferences'] = True
            
            if 'sqlite' in strings or 'database' in strings:
                file_ops['database_usage'] = True
                
        except:
            pass
        
        return file_ops
    
    def _extract_resources(self) -> Dict:
        """Extract resource information"""
        try:
            resources = {
                'files': [],
                'native_libs': [],
            }
            
            # List files in APK
            with ZipFile(self.apk_path, 'r') as zip_file:
                resources['files'] = zip_file.namelist()[:100]  # Limit
                
                # Find native libraries
                resources['native_libs'] = [
                    f for f in resources['files'] 
                    if f.startswith('lib/') and f.endswith('.so')
                ]
            
            return resources
        except:
            return {}
    
    def _fallback_analysis(self) -> Dict:
        """Fallback analysis using zipfile when Androguard not available"""
        try:
            with ZipFile(self.apk_path, 'r') as zip_file:
                files = zip_file.namelist()
                
                return {
                    'success': True,
                    'method': 'zipfile_fallback',
                    'files': files[:100],
                    'has_manifest': 'AndroidManifest.xml' in files,
                    'has_dex': any(f.endswith('.dex') for f in files),
                    'native_libs': [f for f in files if f.startswith('lib/') and f.endswith('.so')],
                    'note': 'Install androguard for full analysis: pip install androguard'
                }
        except Exception as e:
            return {
                'success': False,
                'method': 'fallback',
                'error': str(e)
            }


class CodeAnalyzer:
    """
    Fast code analysis for security patterns
    Optimized for speed
    """
    
    # Security patterns (optimized regex)
    PATTERNS = {
        'hardcoded_secrets': [
            (r'api[_-]?key\s*[:=]\s*["\'][\w-]{20,}["\']', 'API Key'),
            (r'password\s*[:=]\s*["\'][^"\']{4,}["\']', 'Hardcoded Password'),
            (r'secret\s*[:=]\s*["\'][^"\']{4,}["\']', 'Hardcoded Secret'),
            (r'token\s*[:=]\s*["\'][\w-]{20,}["\']', 'Auth Token'),
        ],
        'insecure_crypto': [
            (r'DES|RC4|MD5|SHA1(?!ng)', 'Weak Crypto Algorithm'),
            (r'ECB', 'ECB Mode (Insecure)'),
            (r'mode:\s*["\']ECB["\']', 'ECB Mode'),
        ],
        'insecure_network': [
            (r'http://(?!localhost|127\.0\.0\.1)', 'HTTP URL (Unencrypted)'),
            (r'setHostnameVerifier.*ALLOW_ALL', 'Hostname Verification Disabled'),
            (r'TrustAllCertificates', 'Trust All Certificates'),
        ],
        'webview_issues': [
            (r'setJavaScriptEnabled\s*\(\s*true\s*\)', 'JavaScript Enabled'),
            (r'setAllowFileAccess\s*\(\s*true\s*\)', 'File Access Enabled'),
            (r'loadUrl.*javascript:', 'JavaScript URL Loading'),
        ],
        'insecure_storage': [
            (r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE', 'World Accessible Files'),
            (r'getExternalStorage', 'External Storage Usage'),
            (r'/sdcard/', 'SD Card Path'),
        ],
    }
    
    @staticmethod
    def scan_strings(strings: List[str]) -> List[Dict]:
        """
        Fast string pattern scanning
        Much faster than full decompilation
        """
        findings = []
        combined_text = '\n'.join(strings)
        
        for category, patterns in CodeAnalyzer.PATTERNS.items():
            for pattern, description in patterns:
                try:
                    matches = re.finditer(pattern, combined_text, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        findings.append({
                            'category': category,
                            'description': description,
                            'matched_text': match.group(0)[:100],  # Limit length
                            'severity': 'high' if 'password' in description.lower() else 'medium',
                        })
                except:
                    continue
        
        return findings[:50]  # Limit results
