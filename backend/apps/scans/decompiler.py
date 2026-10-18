"""
Enhanced APK Decompilation Module
Integrates with external tools: apktool, jadx, dex2jar
"""
import os
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Optional


class APKDecompiler:
    """Handles APK decompilation using external tools"""
    
    def __init__(self, apk_path: str, output_dir: str):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.apktool_jar = self._find_apktool()
        self.jadx_bin = self._find_jadx()
        
    def _find_apktool(self) -> Optional[str]:
        """Locate apktool.jar"""
        possible_paths = [
            'tools/apktool.jar',
            '/usr/local/bin/apktool.jar',
            'C:\\tools\\apktool.jar'
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path
        return None
    
    def _find_jadx(self) -> Optional[str]:
        """Locate jadx binary"""
        # Try to find jadx in PATH
        try:
            result = subprocess.run(['jadx', '--version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            if result.returncode == 0:
                return 'jadx'
        except:
            pass
        return None
    
    def decompile_with_apktool(self) -> Dict:
        """
        Decompile APK using apktool
        Extracts: AndroidManifest.xml, resources, smali code
        """
        if not self.apktool_jar:
            return {
                'success': False,
                'method': 'apktool',
                'error': 'apktool not found. Using fallback extraction.'
            }
        
        try:
            output_path = os.path.join(self.output_dir, 'apktool_output')
            cmd = [
                'java', '-jar', self.apktool_jar,
                'd',  # decode
                self.apk_path,
                '-o', output_path,
                '-f'  # force overwrite
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'method': 'apktool',
                    'output_dir': output_path,
                    'has_manifest': os.path.exists(os.path.join(output_path, 'AndroidManifest.xml')),
                    'has_smali': os.path.exists(os.path.join(output_path, 'smali'))
                }
            else:
                return {
                    'success': False,
                    'method': 'apktool',
                    'error': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'method': 'apktool', 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'method': 'apktool', 'error': str(e)}
    
    def decompile_with_jadx(self) -> Dict:
        """
        Decompile DEX to Java using jadx
        Produces readable Java source code
        """
        if not self.jadx_bin:
            return {
                'success': False,
                'method': 'jadx',
                'error': 'jadx not found in PATH'
            }
        
        try:
            output_path = os.path.join(self.output_dir, 'jadx_output')
            cmd = [
                self.jadx_bin,
                '-d', output_path,  # output directory
                '--no-res',  # skip resources
                '--no-src',  # skip sources (we want them, but for speed in demo)
                self.apk_path
            ]
            
            # For actual use, remove --no-src and --no-res
            cmd = [self.jadx_bin, '-d', output_path, self.apk_path]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'method': 'jadx',
                    'output_dir': output_path,
                    'has_sources': os.path.exists(os.path.join(output_path, 'sources'))
                }
            else:
                return {
                    'success': False,
                    'method': 'jadx',
                    'error': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'method': 'jadx', 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'method': 'jadx', 'error': str(e)}
    
    def extract_manifest(self) -> Optional[Dict]:
        """Extract and parse AndroidManifest.xml"""
        # Try apktool output first
        apktool_manifest = os.path.join(self.output_dir, 'apktool_output', 'AndroidManifest.xml')
        
        if os.path.exists(apktool_manifest):
            return self._parse_manifest(apktool_manifest)
        
        return None
    
    def _parse_manifest(self, manifest_path: str) -> Dict:
        """Parse AndroidManifest.xml"""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract key information
            manifest_info = {
                'package': root.get('package'),
                'version_code': root.get('{http://schemas.android.com/apk/res/android}versionCode'),
                'version_name': root.get('{http://schemas.android.com/apk/res/android}versionName'),
                'permissions': [],
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': []
            }
            
            # Extract permissions
            for perm in root.findall('.//uses-permission'):
                name = perm.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    manifest_info['permissions'].append(name)
            
            # Extract components
            application = root.find('application')
            if application:
                for activity in application.findall('activity'):
                    name = activity.get('{http://schemas.android.com/apk/res/android}name')
                    if name:
                        manifest_info['activities'].append(name)
                
                for service in application.findall('service'):
                    name = service.get('{http://schemas.android.com/apk/res/android}name')
                    if name:
                        manifest_info['services'].append(name)
                
                for receiver in application.findall('receiver'):
                    name = receiver.get('{http://schemas.android.com/apk/res/android}name')
                    if name:
                        manifest_info['receivers'].append(name)
            
            return manifest_info
            
        except Exception as e:
            return {'error': str(e)}


class CodeAnalyzer:
    """Analyzes decompiled code for security issues"""
    
    def __init__(self, source_dir: str):
        self.source_dir = source_dir
        
    def scan_for_patterns(self, patterns: Dict[str, str]) -> List[Dict]:
        """Scan source files for security patterns"""
        findings = []
        
        if not os.path.exists(self.source_dir):
            return findings
        
        # Walk through all Java files
        for root, dirs, files in os.walk(self.source_dir):
            for file in files:
                if file.endswith('.java') or file.endswith('.smali'):
                    file_path = os.path.join(root, file)
                    findings.extend(self._scan_file(file_path, patterns))
        
        return findings
    
    def _scan_file(self, file_path: str, patterns: Dict[str, str]) -> List[Dict]:
        """Scan a single file for patterns"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    for pattern_name, pattern in patterns.items():
                        import re
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append({
                                'file': file_path,
                                'line': line_num,
                                'pattern': pattern_name,
                                'content': line.strip()
                            })
        except Exception as e:
            pass
        
        return findings


class YARAScanner:
    """YARA-based malware detection"""
    
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.rules_loaded = False
        
        try:
            import yara
            self.yara = yara
            self.rules_loaded = True
        except ImportError:
            self.yara = None
    
    def scan(self) -> List[Dict]:
        """Scan APK with YARA rules"""
        if not self.rules_loaded:
            return [{
                'rule': 'YARA',
                'status': 'not_available',
                'message': 'Install yara-python for malware detection'
            }]
        
        findings = []
        
        # Define basic YARA rules
        rules_source = r'''
        rule SuspiciousAPI {
            strings:
                $api1 = "Runtime.exec"
                $api2 = "ProcessBuilder"
                $api3 = "getRuntime"
            condition:
                any of them
        }
        
        rule Obfuscation {
            strings:
                $obf1 = /[a-z]{1,2}\.[a-z]{1,2}\.[a-z]{1,2}/
            condition:
                #obf1 > 10
        }
        '''
        
        try:
            rules = self.yara.compile(source=rules_source)
            matches = rules.match(self.apk_path)
            
            for match in matches:
                findings.append({
                    'rule': match.rule,
                    'tags': match.tags,
                    'strings': [str(s) for s in match.strings]
                })
        except Exception as e:
            findings.append({
                'rule': 'YARA_ERROR',
                'error': str(e)
            })
        
        return findings
