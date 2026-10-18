"""
Comprehensive Static Analysis Module
Extracts all artifacts: strings, URLs, IPs, emails, files, domains, etc.
"""
import re
import json
from typing import Dict, List, Set
from zipfile import ZipFile
from pathlib import Path


class StaticAnalyzer:
    """
    Comprehensive static analysis for APK files
    Extracts all artifacts
    """
    
    def __init__(self, apk_path: str, androguard_apk=None):
        self.apk_path = apk_path
        self.apk = androguard_apk
        self.all_strings = set()
        
    def analyze(self) -> Dict:
        """Perform comprehensive static analysis"""
        # Extract all strings from APK
        self._collect_all_strings()
        
        return {
            'strings': self._extract_all_strings(),
            'urls': self._extract_urls(),
            'domains': self._extract_domains(),
            'emails': self._extract_emails(),
            'ip_addresses': self._extract_ips(),
            'file_paths': self._extract_file_paths(),
            'base64_strings': self._extract_base64(),
            'crypto_keys': self._extract_crypto_keys(),
            'api_keys': self._extract_api_keys(),
            'firebase': self._extract_firebase(),
            'aws': self._extract_aws(),
            'code_secrets': self._find_secrets(),
            'interesting_strings': self._extract_interesting_strings(),
            'files_list': self._list_apk_files(),
        }
    
    def _collect_all_strings(self):
        """Collect all strings from APK (DEX + resources + manifest)"""
        try:
            # From Androguard APK object
            if self.apk:
                # Get strings from resources
                try:
                    resources = self.apk.get_android_resources_package()
                    if resources:
                        for string_val in resources.get_strings_resources().values():
                            if isinstance(string_val, str):
                                self.all_strings.add(string_val)
                except:
                    pass
                
                # Get strings from DEX files
                try:
                    for dex in self.apk.get_all_dex():
                        for string in dex.get_strings():
                            self.all_strings.add(string)
                except:
                    pass
            
            # Also extract from ZIP directly
            try:
                with ZipFile(self.apk_path, 'r') as zf:
                    for filename in zf.namelist():
                        if filename.endswith(('.xml', '.json', '.txt', '.properties')):
                            try:
                                content = zf.read(filename).decode('utf-8', errors='ignore')
                                # Split into words/strings
                                strings = re.findall(r'[a-zA-Z0-9_./\-:@]+', content)
                                self.all_strings.update(s for s in strings if len(s) > 3)
                            except:
                                pass
            except:
                pass
                
        except Exception as e:
            print(f"Error collecting strings: {e}")
    
    def _extract_all_strings(self) -> List[str]:
        """Get all extracted strings (filtered)"""
        filtered = []
        for s in self.all_strings:
            # Filter out very short or binary strings
            if len(s) >= 4 and len(s) < 500:
                # Check if mostly printable
                printable_ratio = sum(c.isprintable() for c in s) / len(s)
                if printable_ratio > 0.8:
                    filtered.append(s)
        
        return sorted(list(set(filtered)))[:2000]  # Limit to 2000 strings
    
    def _extract_urls(self) -> List[Dict]:
        """Extract all URLs with context"""
        url_pattern = re.compile(
            r'(https?://[^\s<>"{}|\\^`\[\]\']+)',
            re.IGNORECASE
        )
        
        urls = []
        seen = set()
        
        for string in self.all_strings:
            matches = url_pattern.findall(str(string))
            for url in matches:
                if url not in seen and len(url) > 10:
                    seen.add(url)
                    urls.append({
                        'url': url,
                        'scheme': 'https' if url.startswith('https') else 'http',
                        'is_secure': url.startswith('https'),
                    })
        
        return urls[:200]  # Limit
    
    def _extract_domains(self) -> List[str]:
        """Extract domain names"""
        domain_pattern = re.compile(
            r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
            re.IGNORECASE
        )
        
        domains = set()
        for string in self.all_strings:
            matches = domain_pattern.findall(str(string))
            domains.update(matches)
        
        # Filter out common Android domains
        filtered = [d for d in domains if not d.endswith(('.local', '.arpa'))]
        return sorted(list(set(filtered)))[:100]
    
    def _extract_emails(self) -> List[str]:
        """Extract email addresses"""
        email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        
        emails = set()
        for string in self.all_strings:
            matches = email_pattern.findall(str(string))
            emails.update(matches)
        
        return sorted(list(emails))[:50]
    
    def _extract_ips(self) -> List[Dict]:
        """Extract IP addresses"""
        ipv4_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        ipv6_pattern = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
        
        ips = []
        seen = set()
        
        for string in self.all_strings:
            # IPv4
            for ip in ipv4_pattern.findall(str(string)):
                if ip not in seen and not ip.startswith(('0.', '127.', '255.')):
                    seen.add(ip)
                    ips.append({'address': ip, 'type': 'IPv4'})
            
            # IPv6
            for ip in ipv6_pattern.findall(str(string)):
                if ip not in seen:
                    seen.add(ip)
                    ips.append({'address': ip, 'type': 'IPv6'})
        
        return ips[:50]
    
    def _extract_file_paths(self) -> List[str]:
        """Extract file paths and directories"""
        path_patterns = [
            r'/[a-zA-Z0-9_\-./]+',  # Unix paths
            r'[A-Z]:\\[a-zA-Z0-9_\-\\./]+',  # Windows paths
            r'file://[^\s]+',  # File URLs
        ]
        
        paths = set()
        for string in self.all_strings:
            for pattern in path_patterns:
                matches = re.findall(pattern, str(string))
                for path in matches:
                    if len(path) > 5 and ('/' in path or '\\' in path):
                        paths.add(path)
        
        return sorted(list(paths))[:100]
    
    def _extract_base64(self) -> List[str]:
        """Extract potential Base64 encoded strings"""
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        
        base64_strings = set()
        for string in self.all_strings:
            matches = base64_pattern.findall(str(string))
            for match in matches:
                if len(match) >= 20 and len(match) <= 200:
                    base64_strings.add(match)
        
        return list(base64_strings)[:50]
    
    def _extract_crypto_keys(self) -> Dict:
        """Detect cryptographic keys and certificates"""
        patterns = {
            'private_keys': re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
            'public_keys': re.compile(r'-----BEGIN PUBLIC KEY-----'),
            'certificates': re.compile(r'-----BEGIN CERTIFICATE-----'),
            'ssh_keys': re.compile(r'ssh-rsa|ssh-ed25519'),
        }
        
        findings = {
            'private_keys': [],
            'public_keys': [],
            'certificates': [],
            'ssh_keys': [],
        }
        
        all_text = '\n'.join(self.all_strings)
        
        for key_type, pattern in patterns.items():
            matches = pattern.findall(all_text)
            if matches:
                findings[key_type] = [f"Found {len(matches)} {key_type.replace('_', ' ')}"]
        
        return findings
    
    def _extract_api_keys(self) -> List[Dict]:
        """Detect API keys and tokens"""
        patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'google_api': r'AIza[0-9A-Za-z\\-_]{35}',
            'slack_token': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
            'github_token': r'ghp_[a-zA-Z0-9]{36}',
            'stripe_key': r'sk_live_[0-9a-zA-Z]{24}',
            'generic_key': r'(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[\s:=]+[\'"]?([a-zA-Z0-9_\-]{20,})',
        }
        
        findings = []
        all_text = '\n'.join(self.all_strings)
        
        for key_type, pattern in patterns.items():
            matches = re.findall(pattern, all_text)
            for match in matches:
                finding = {
                    'type': key_type,
                    'value': match if isinstance(match, str) else match[1] if len(match) > 1 else match[0],
                }
                findings.append(finding)
        
        return findings[:20]
    
    def _extract_firebase(self) -> Dict:
        """Extract Firebase configuration"""
        firebase = {
            'found': False,
            'urls': [],
            'config': {}
        }
        
        all_text = '\n'.join(self.all_strings)
        
        # Firebase URLs
        firebase_urls = re.findall(r'https://[a-z0-9\-]+\.firebaseio\.com', all_text)
        if firebase_urls:
            firebase['found'] = True
            firebase['urls'] = list(set(firebase_urls))
        
        # Firebase config keys
        config_patterns = {
            'project_id': r'firebase[_-]?project[_-]?id[\s:=]+[\'"]?([a-z0-9\-]+)',
            'app_id': r'firebase[_-]?app[_-]?id[\s:=]+[\'"]?([a-zA-Z0-9:_\-]+)',
            'api_key': r'firebase[_-]?api[_-]?key[\s:=]+[\'"]?([a-zA-Z0-9_\-]+)',
        }
        
        for key, pattern in config_patterns.items():
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            if matches:
                firebase['config'][key] = matches[0]
                firebase['found'] = True
        
        return firebase if firebase['found'] else None
    
    def _extract_aws(self) -> Dict:
        """Extract AWS configuration"""
        aws = {
            'found': False,
            's3_buckets': [],
            'regions': [],
        }
        
        all_text = '\n'.join(self.all_strings)
        
        # S3 buckets
        s3_patterns = [
            r'https://([a-z0-9\-]+)\.s3\.amazonaws\.com',
            r's3://([a-z0-9\-]+)',
            r'https://s3\.amazonaws\.com/([a-z0-9\-]+)',
        ]
        
        for pattern in s3_patterns:
            matches = re.findall(pattern, all_text)
            aws['s3_buckets'].extend(matches)
        
        if aws['s3_buckets']:
            aws['found'] = True
            aws['s3_buckets'] = list(set(aws['s3_buckets']))
        
        # AWS regions
        region_pattern = r'(us|eu|ap|sa|ca|me|af)-(north|south|east|west|central)-[0-9]'
        regions = re.findall(region_pattern, all_text)
        if regions:
            aws['found'] = True
            aws['regions'] = list(set([f"{r[0]}-{r[1]}" for r in regions]))
        
        return aws if aws['found'] else None
    
    def _find_secrets(self) -> List[Dict]:
        """Find potential secrets and sensitive data"""
        secrets = []
        
        # Patterns for secrets
        secret_keywords = [
            'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
            'access_token', 'auth_token', 'private_key', 'client_secret', 'db_password'
        ]
        
        for string in self.all_strings:
            lower = string.lower()
            for keyword in secret_keywords:
                if keyword in lower and len(string) > len(keyword) + 5:
                    # Extract potential value
                    match = re.search(rf'{keyword}[\s:=]+[\'"]?([^\s\'"]+)', lower)
                    if match:
                        secrets.append({
                            'keyword': keyword,
                            'context': string[:100],
                        })
        
        return secrets[:30]
    
    def _extract_interesting_strings(self) -> Dict:
        """Extract categorized interesting strings"""
        categories = {
            'sql_queries': [],
            'file_operations': [],
            'network_operations': [],
            'crypto_operations': [],
            'debug_logs': [],
        }
        
        sql_keywords = [
            'select', 'insert', 'update', 'delete', 'replace', 'upsert',
            'from', 'where', 'join', 'inner join', 'left join', 'right join', 'full join',
            'union', 'union all', 'order by', 'group by', 'having', 'limit', 'offset',
            'create table', 'alter table', 'drop table', 'truncate table', 'rename table',
            'create index', 'drop index', 'create view', 'drop view',
            'primary key', 'foreign key', 'unique constraint', 'check constraint',
            'begin transaction', 'commit', 'rollback', 'savepoint',
            'pragma', 'sqlite_master', 'rawquery', 'execsql', 'query(',
            'contentvalues', 'sqlitedatabase', 'roomdatabase',
            'grant', 'revoke', 'information_schema', 'sysobjects', 'xp_cmdshell'
        ]
        file_keywords = [
            'fopen', 'fclose', 'fread', 'fwrite', 'fgets', 'fprintf', 'fscanf', 'fflush',
            'open(', 'close(', 'read(', 'write(', 'append',
            'openfile', 'readfile', 'writefile', 'deletefile', 'renamefile', 'copyfile', 'movefile',
            'fileinputstream', 'fileoutputstream', 'bufferedreader', 'bufferedwriter',
            'filereader', 'filewriter', 'randomaccessfile', 'scanner(',
            'java.io.file', 'java.nio.file', 'files.readallbytes', 'files.readalllines',
            'files.write', 'filechannel', 'memorymappedfile',
            'getfilesdir', 'getexternalfilesdir', 'getcachedir', 'getexternalstoragedirectory',
            'sharedpreferences', 'androidmanifest.xml', 'contentresolver', 'openinputstream', 'openoutputstream',
            'tmp/', '/data/data/', '/sdcard/', '/storage/emulated/'
        ]
        network_keywords = [
            'httpurlconnection', 'httpsurlconnection', 'urlconnection',
            'okhttp', 'okhttpclient', 'retrofit', 'volley', 'ion', 'fuel',
            'socket', 'serversocket', 'datagramsocket', 'sslcontext', 'sslsocket',
            'connect', 'bind', 'listen', 'accept', 'send', 'recv',
            'request', 'response', 'get(', 'post(', 'put(', 'patch(', 'delete(',
            'websocket', 'stomp', 'mqtt', 'grpc',
            'dns', 'inetaddress', 'hostnameverifier', 'trustmanager',
            'certificatepinner', 'x509trustmanager', 'networksecurityconfig',
            'http://', 'https://', 'ws://', 'wss://',
            'api.', '/api/', 'graphql', 'rest', 'soap', 'rpc',
            'user-agent', 'authorization', 'bearer ', 'basic '
        ]
        crypto_keywords = [
            'cipher', 'messagedigest', 'keygenerator', 'secretkey', 'secretkeyspec',
            'publickey', 'privatekey', 'keystore', 'keypair', 'keypairgenerator',
            'encrypt', 'decrypt', 'sign', 'verify', 'hash', 'hmac', 'mac.getinstance',
            'aes', 'des', '3des', 'desede', 'rsa', 'ec', 'ecdsa', 'ecdh',
            'sha1', 'sha-1', 'sha256', 'sha-256', 'sha384', 'sha-384', 'sha512', 'sha-512',
            'md5', 'pbkdf2', 'bcrypt', 'scrypt', 'argon2',
            'gcm', 'cbc', 'ecb', 'ctr', 'ofb', 'cfb',
            'ivparameter', 'gcmparameterspec', 'pbespec', 'salt', 'nonce',
            'x509certificate', 'certificatefactory', 'truststore', 'bouncycastle',
            'javax.crypto', 'java.security', 'androidkeystore'
        ]
        debug_keywords = [
            'log.d', 'log.e', 'log.w', 'log.i', 'log.v', 'log.wtf',
            'system.out', 'system.err', 'printstacktrace', 'traceback',
            'debug', 'verbose', 'println', 'print(', 'console.log',
            'timber.d', 'timber.e', 'timber.w', 'timber.i', 'timber.v',
            'adb logcat', 'strictmode', 'debuggable', 'buildconfig.debug',
            'assert', 'exception', 'stack trace', 'uncaughtexceptionhandler'
        ]
        
        for string in self.all_strings:
            lower_string = str(string).lower()
            # SQL
            if any(kw in lower_string for kw in sql_keywords):
                categories['sql_queries'].append(string[:200])
            
            # File ops
            if any(kw in lower_string for kw in file_keywords):
                categories['file_operations'].append(string[:150])
            
            # Network
            if any(kw in lower_string for kw in network_keywords):
                categories['network_operations'].append(string[:150])
            
            # Crypto
            if any(kw in lower_string for kw in crypto_keywords):
                categories['crypto_operations'].append(string[:150])
            
            # Debug
            if any(kw in lower_string for kw in debug_keywords):
                categories['debug_logs'].append(string[:150])
        
        # Limit each category
        for key in categories:
            categories[key] = categories[key][:20]
        
        return categories
    
    def _list_apk_files(self) -> Dict:
        """List all files in APK with categorization"""
        files = {
            'dex_files': [],
            'so_libraries': [],
            'resources': [],
            'assets': [],
            'other': [],
            'total_count': 0,
        }
        
        try:
            with ZipFile(self.apk_path, 'r') as zf:
                for filename in zf.namelist():
                    files['total_count'] += 1
                    
                    if filename.endswith('.dex'):
                        files['dex_files'].append(filename)
                    elif filename.endswith('.so'):
                        files['so_libraries'].append(filename)
                    elif filename.startswith('res/'):
                        files['resources'].append(filename)
                    elif filename.startswith('assets/'):
                        files['assets'].append(filename)
                    else:
                        files['other'].append(filename)
        except Exception as e:
            files['error'] = str(e)
        
        # Limit file lists
        for key in ['resources', 'assets', 'other']:
            if len(files[key]) > 100:
                files[key] = files[key][:100] + [f"... and {len(files[key]) - 100} more"]
        
        return files
