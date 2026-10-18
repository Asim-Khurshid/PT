from rest_framework import viewsets, status, permissions, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from django.utils import timezone
from django.http import FileResponse
import hashlib
import threading
import os
from .models import Scan, Vulnerability, Permission, Report
from .serializers import ScanSerializer, ScanCreateSerializer, ReportSerializer
from .tasks import analyze_apk, cancel_analysis

# Track running analyses for cancellation
running_analyses = {}

class ScanViewSet(viewsets.ModelViewSet):
    serializer_class = ScanSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['app_name', 'package_name']
    ordering_fields = ['created_at', 'threat_score']
    ordering = ['-created_at']

    def get_queryset(self):
        return Scan.objects.filter(user=self.request.user)

    @action(detail=False, methods=['post'])
    def upload(self, request):
        global running_analyses
        serializer = ScanCreateSerializer(data=request.data)
        if serializer.is_valid():
            file_obj = request.FILES.get('file_path')
            if not file_obj:
                return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)

            # Calculate file hashes
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            
            for chunk in file_obj.chunks():
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
            
            hash_md5_str = md5_hash.hexdigest()
            hash_sha256_str = sha256_hash.hexdigest()
            
            # Extract package name and version from APK if not provided
            package_name = serializer.validated_data.get('package_name', '')
            version = ''
            if not package_name:
                try:
                    from .decompiler_androguard import AndroguardDecompiler
                    from androguard.core.apk import APK
                    import tempfile
                    # Save file temporarily to extract metadata
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
                        for chunk in file_obj.chunks():
                            tmp_file.write(chunk)
                        tmp_path = tmp_file.name
                    
                    decompiler = AndroguardDecompiler(tmp_path, None)
                    apk_obj = decompiler.apk or APK(tmp_path)
                    package_name = apk_obj.get_package() or 'unknown'
                    version_name = apk_obj.get_androidversion_name()
                    version_code = apk_obj.get_androidversion_code()
                    version = f"{version_name} ({version_code})" if version_name else str(version_code) if version_code else ''
                    os.unlink(tmp_path)  # Clean up temp file
                except Exception as e:
                    print(f"Package extraction error: {str(e)}")
                    package_name = 'unknown'
                    version = ''
            
            # Check if APK already exists for THIS USER
            existing_scan = Scan.objects.filter(
                user=request.user,
                hash_md5=hash_md5_str
            ).first()

            static_enabled = serializer.validated_data.get('static_analysis_enabled', True)
            dynamic_enabled = serializer.validated_data.get('dynamic_analysis_enabled', False)
            fuzzing_enabled = serializer.validated_data.get('fuzzing_enabled', False)
            ai_enabled = serializer.validated_data.get('ai_analysis_enabled', True)
            
            if existing_scan:
                same_static = existing_scan.static_analysis_enabled == static_enabled
                same_dynamic = existing_scan.dynamic_analysis_enabled == dynamic_enabled
                same_fuzzing = existing_scan.fuzzing_enabled == fuzzing_enabled
                same_ai = existing_scan.ai_analysis_enabled == ai_enabled

                if same_static and same_dynamic and same_fuzzing and same_ai:
                    # Return existing scan for this user
                    return Response({
                        'message': 'You have already scanned this APK',
                        'scan': ScanSerializer(existing_scan).data,
                        'existing': True,
                        'id': existing_scan.id
                    }, status=status.HTTP_200_OK)

                existing_scan.static_analysis_enabled = static_enabled
                existing_scan.dynamic_analysis_enabled = dynamic_enabled
                existing_scan.fuzzing_enabled = fuzzing_enabled
                existing_scan.ai_analysis_enabled = ai_enabled
                existing_scan.status = 'pending'
                existing_scan.error_message = None
                existing_scan.started_at = timezone.now()
                existing_scan.completed_at = None
                existing_scan.threat_level = 'safe'
                existing_scan.threat_score = 0
                existing_scan.total_issues = 0
                existing_scan.critical_issues = 0
                existing_scan.high_issues = 0
                existing_scan.medium_issues = 0
                existing_scan.low_issues = 0
                existing_scan.static_analysis = {}
                existing_scan.dynamic_analysis = {}
                existing_scan.fuzzing_analysis = {}
                existing_scan.save()

                existing_scan.vulnerabilities.all().delete()
                existing_scan.permissions.all().delete()
                if hasattr(existing_scan, 'report'):
                    existing_scan.report.delete()

                thread = threading.Thread(target=analyze_apk, args=(existing_scan.id,))
                thread.daemon = True
                thread.start()

                running_analyses[existing_scan.id] = thread

                return Response({
                    'message': 'Re-analyzing APK with updated options',
                    'scan': ScanSerializer(existing_scan).data,
                    'existing': False,
                    'id': existing_scan.id
                }, status=status.HTTP_200_OK)

            scan = serializer.save(
                user=request.user,
                file_path=file_obj,
                file_name=file_obj.name,
                file_size=file_obj.size,
                package_name=package_name,
                version=version,
                hash_md5=hash_md5_str,
                hash_sha256=hash_sha256_str,
                status='pending',
                static_analysis_enabled=static_enabled,
                dynamic_analysis_enabled=dynamic_enabled,
                fuzzing_enabled=fuzzing_enabled,
                ai_analysis_enabled=ai_enabled
            )

            # Trigger analysis in background thread
            # In production, use Celery: analyze_apk.delay(scan.id)
            thread = threading.Thread(target=analyze_apk, args=(scan.id,))
            thread.daemon = True
            thread.start()
            
            # Track the running analysis
            running_analyses[scan.id] = thread

            return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['get'])
    def status(self, request, pk=None):
        """Get scan status and progress"""
        scan = self.get_object()
        return Response({
            'id': scan.id,
            'status': scan.status,
            'threat_level': scan.threat_level,
            'threat_score': scan.threat_score,
            'total_issues': scan.total_issues,
            'started_at': scan.started_at,
            'completed_at': scan.completed_at
        })

    @action(detail=True, methods=['get'])
    def report(self, request, pk=None):
        scan = self.get_object()
        try:
            report = scan.report
            serializer = ReportSerializer(report)
            return Response(serializer.data)
        except Report.DoesNotExist:
            # Check if scan is still processing
            if scan.status in ['pending', 'scanning']:
                return Response({
                    'message': 'Report is being generated',
                    'status': scan.status
                }, status=status.HTTP_202_ACCEPTED)
            return Response({'error': 'Report not found'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        scans = self.get_queryset()
        return Response({
            'total_scans': scans.count(),
            'critical_threats': scans.filter(threat_level='critical').count(),
            'high_threats': scans.filter(threat_level='high').count(),
            'medium_threats': scans.filter(threat_level='medium').count(),
            'safe_apps': scans.filter(threat_level='safe').count(),
        })

    @action(detail=True, methods=['post'])
    def rescan(self, request, pk=None):
        """Retry a failed or incomplete scan"""
        scan = self.get_object()
        
        # Clear previous errors
        scan.status = 'pending'
        scan.error_message = None
        scan.started_at = timezone.now()
        scan.completed_at = None
        scan.save()
        
        # Clear previous results
        scan.vulnerabilities.all().delete()
        scan.permissions.all().delete()
        if hasattr(scan, 'report'):
            scan.report.delete()
        
        # Restart analysis
        thread = threading.Thread(target=analyze_apk, args=(scan.id,))
        thread.daemon = True
        thread.start()
        
        # Track the running analysis
        global running_analyses
        running_analyses[scan.id] = thread
        
        return Response({
            'message': 'Scan restarted successfully',
            'scan': ScanSerializer(scan).data
        })

    @action(detail=True, methods=['post'])
    def cancel_scan(self, request, pk=None):
        """Cancel an ongoing scan"""
        scan = self.get_object()
        
        if scan.status not in ['pending', 'scanning']:
            return Response({
                'error': 'Can only cancel pending or scanning scans',
                'status': scan.status
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Mark scan as cancelled
        scan.status = 'failed'
        scan.error_message = 'Analysis cancelled by user'
        scan.completed_at = timezone.now()
        scan.save()
        
        # Signal cancellation in the analysis task
        cancel_analysis(scan.id)
        
        # Remove from running analyses
        global running_analyses
        if scan.id in running_analyses:
            del running_analyses[scan.id]
        
        return Response({
            'message': 'Scan cancelled successfully',
            'scan': ScanSerializer(scan).data
        })

    @action(detail=False, methods=['post'])
    def cleanup_failed(self, request):
        """Auto-cleanup failed scans and retry them"""
        failed_scans = Scan.objects.filter(
            user=request.user,
            status='failed'
        )
        
        cleaned_count = 0
        retried_count = 0
        
        for scan in failed_scans:
            # Clear old data
            scan.vulnerabilities.all().delete()
            scan.permissions.all().delete()
            if hasattr(scan, 'report'):
                scan.report.delete()
            
            # Retry the scan
            scan.status = 'pending'
            scan.error_message = None
            scan.started_at = timezone.now()
            scan.completed_at = None
            scan.save()
            
            # Restart analysis
            thread = threading.Thread(target=analyze_apk, args=(scan.id,))
            thread.daemon = True
            thread.start()
            
            cleaned_count += 1
            retried_count += 1
        
        return Response({
            'message': f'Cleaned and retried {cleaned_count} failed scans',
            'cleaned': cleaned_count,
            'retried': retried_count
        })

    @action(detail=True, methods=['post'])
    def delete_scan(self, request, pk=None):
        """Delete scan and its associated APK file"""
        scan = self.get_object()
        app_name = scan.app_name
        
        try:
            scan.delete()
            return Response({
                'message': f'Scan for {app_name} and its APK file deleted successfully'
            }, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({
                'error': f'Failed to delete scan: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'])
    def download_pdf(self, request, pk=None):
        """Download PDF security report"""
        scan = self.get_object()
        
        # Check if scan is completed
        if scan.status != 'completed':
            return Response({
                'error': 'Scan is not completed yet',
                'status': scan.status
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            report = scan.report
            
            if not report.pdf_url:
                return Response({
                    'error': 'PDF report not available for this scan'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Construct full path to PDF
            pdf_path = os.path.join('media', report.pdf_url)
            
            if not os.path.exists(pdf_path):
                return Response({
                    'error': 'PDF file not found'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Return PDF file
            response = FileResponse(
                open(pdf_path, 'rb'),
                content_type='application/pdf',
                as_attachment=True,
                filename=f"{scan.app_name}_security_report.pdf"
            )
            return response
            
        except Report.DoesNotExist:
            return Response({
                'error': 'Report not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'error': f'Error downloading PDF: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=True, methods=['get'], url_path='view-file')
    def view_file(self, request, pk=None):
        """View decompiled source file or APK file content"""
        scan = self.get_object()
        file_path = request.query_params.get('path', '')
        
        if not file_path:
            return Response({'error': 'File path required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            import zipfile
            from androguard.core.apk import APK
            
            # Special handling for AndroidManifest.xml - it's in binary format
            if file_path == 'AndroidManifest.xml':
                try:
                    apk = APK(scan.file_path.path)
                    # get_android_manifest_xml returns an Element, convert to string
                    import xml.etree.ElementTree as ET
                    xml_element = apk.get_android_manifest_xml()
                    xml_string = ET.tostring(xml_element, encoding='unicode')
                    # Pretty print it
                    import xml.dom.minidom
                    dom = xml.dom.minidom.parseString(xml_string)
                    xml_content = dom.toprettyxml(indent='  ')
                    return Response({
                        'content': xml_content,
                        'type': 'xml',
                        'path': file_path
                    })
                except Exception as e:
                    return Response({
                        'error': f'Failed to decode AndroidManifest.xml: {str(e)}'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # For other XML files in res/, also try Androguard decoding
            if file_path.endswith('.xml') and file_path.startswith('res/'):
                try:
                    apk = APK(scan.file_path.path)
                    # Get the decoded XML using Androguard's AXMLPrinter
                    from androguard.core.axml import AXMLPrinter
                    with zipfile.ZipFile(scan.file_path.path, 'r') as zip_ref:
                        if file_path in zip_ref.namelist():
                            binary_xml = zip_ref.read(file_path)
                            try:
                                axml = AXMLPrinter(binary_xml)
                                xml_content = axml.get_xml_obj().toprettyxml(indent='  ')
                                return Response({
                                    'content': xml_content,
                                    'type': 'xml',
                                    'path': file_path
                                })
                            except Exception:
                                # If not binary XML, try as plain text
                                pass
                except Exception:
                    pass
            
            # For other files, extract from APK as text
            try:
                with zipfile.ZipFile(scan.file_path.path, 'r') as zip_ref:
                    # Check if file exists in APK
                    if file_path not in zip_ref.namelist():
                        return Response({
                            'error': f'File "{file_path}" not found in APK'
                        }, status=status.HTTP_404_NOT_FOUND)
                    
                    content = zip_ref.read(file_path)
                    
                    # Try to decode as text
                    try:
                        text_content = content.decode('utf-8')
                        file_type = 'xml' if file_path.endswith('.xml') else 'text'
                        return Response({
                            'content': text_content,
                            'type': file_type,
                            'path': file_path
                        })
                    except UnicodeDecodeError:
                        return Response({
                            'error': 'File is binary and cannot be displayed as text',
                            'type': 'binary'
                        }, status=status.HTTP_400_BAD_REQUEST)
            except zipfile.BadZipFile:
                return Response({
                    'error': 'Invalid APK file'
                }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            return Response({
                'error': f'Failed to read file: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'])
    def certificate_info(self, request, pk=None):
        """Get APK certificate information"""
        scan = self.get_object()
        
        try:
            from androguard.core.apk import APK
            
            apk = APK(scan.file_path.path)
            cert = apk.get_certificate()
            
            if not cert:
                return Response({
                    'error': 'No certificate found in APK'
                }, status=status.HTTP_404_NOT_FOUND)
            
            cert_data = {
                'issuer': cert.issuer,
                'subject': cert.subject,
                'serial_number': str(cert.serial_number),
                'not_before': str(cert.not_valid_before),
                'not_after': str(cert.not_valid_after),
                'version': cert.version,
                'signature_algorithm': cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid),
            }
            
            return Response({
                'certificate': cert_data,
                'timestamp': scan.updated_at
            })
        except Exception as e:
            return Response({
                'error': f'Failed to extract certificate info: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'])
    def strings_extraction(self, request, pk=None):
        """Extract and analyze interesting strings from APK"""
        scan = self.get_object()
        
        try:
            from androguard.core.apk import APK
            import re
            
            apk = APK(scan.file_path.path)
            
            # Extract strings from dex files
            urls = set()
            emails = set()
            ips = set()
            suspicious_strings = set()
            
            url_pattern = re.compile(r'https?://[^\s\x00]+', re.IGNORECASE)
            email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
            ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
            suspicious_keywords = [
                'admin', 'password', 'token', 'secret', 'key', 'cipher', 'encrypt',
                'decrypt', 'backdoor', 'malware', 'command', 'shell', 'execute'
            ]
            
            for dex in apk.get_dex():
                strings = dex.get_strings()
                
                for s in strings[:5000]:  # Limit to first 5000 strings
                    if url_pattern.search(s):
                        urls.add(s)
                    if email_pattern.search(s):
                        emails.add(s)
                    if ip_pattern.search(s):
                        ips.add(s)
                    
                    s_lower = s.lower()
                    for keyword in suspicious_keywords:
                        if keyword in s_lower and len(s) > 4:
                            suspicious_strings.add(s)
                            break
            
            return Response({
                'urls': list(urls)[:50],
                'emails': list(emails)[:50],
                'ip_addresses': list(ips)[:50],
                'suspicious_strings': list(suspicious_strings)[:100],
                'statistics': {
                    'total_urls': len(urls),
                    'total_emails': len(emails),
                    'total_ips': len(ips),
                    'suspicious_count': len(suspicious_strings)
                }
            })
        except Exception as e:
            return Response({
                'error': f'Failed to extract strings: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'])
    def entropy_analysis(self, request, pk=None):
        """Analyze file entropy for potential encryption/obfuscation"""
        scan = self.get_object()
        
        try:
            import math
            
            def calculate_entropy(data):
                """Calculate Shannon entropy of data"""
                if not data:
                    return 0
                
                entropy = 0
                for i in range(256):
                    freq = data.count(bytes([i]))
                    if freq > 0:
                        p = freq / len(data)
                        entropy -= p * math.log2(p)
                
                return entropy
            
            with open(scan.file_path.path, 'rb') as f:
                data = f.read()
            
            total_entropy = calculate_entropy(data)
            
            # Analyze chunks
            chunk_size = 4096
            chunks_entropy = []
            
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i+chunk_size]
                entropy = calculate_entropy(chunk)
                chunks_entropy.append({
                    'offset': i,
                    'entropy': round(entropy, 2)
                })
            
            # High entropy (>7.5) might indicate encryption/compression
            high_entropy_chunks = [c for c in chunks_entropy if c['entropy'] > 7.5]
            
            return Response({
                'total_file_entropy': round(total_entropy, 2),
                'file_size': len(data),
                'chunk_size': chunk_size,
                'chunks_analyzed': len(chunks_entropy),
                'high_entropy_chunks': len(high_entropy_chunks),
                'entropy_average': round(sum(c['entropy'] for c in chunks_entropy) / len(chunks_entropy), 2) if chunks_entropy else 0,
                'potential_encryption': total_entropy > 7.5,
                'top_entropy_chunks': sorted(chunks_entropy, key=lambda x: x['entropy'], reverse=True)[:10]
            })
        except Exception as e:
            return Response({
                'error': f'Failed to analyze entropy: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    @action(detail=True, methods=['get'])
    def decompiled_sources(self, request, pk=None):
        """Get decompiled source code analysis"""
        scan = self.get_object()
        
        try:
            from androguard.core.apk import APK
            
            apk = APK(scan.file_path.path)
            
            # Analyze class structure
            classes = []
            for dex in apk.get_dex():
                for cls in dex.get_classes():
                    class_name = cls.get_name()
                    class_info = {
                        'name': class_name,
                        'methods': len(cls.get_methods()),
                        'fields': len(cls.get_fields()),
                        'is_public': 'public' in cls.get_access_flags_string(),
                        'superclass': cls.get_superclass() or 'None'
                    }
                    classes.append(class_info)
            
            return Response({
                'total_classes': len(classes),
                'top_classes': sorted(classes, key=lambda x: x['methods'], reverse=True)[:20],
                'average_methods_per_class': round(sum(c['methods'] for c in classes) / len(classes)) if classes else 0,
                'public_classes': len([c for c in classes if c['is_public']]),
                'timestamp': scan.updated_at
            })
        except Exception as e:
            return Response({
                'error': f'Failed to analyze sources: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'])
    def native_libraries(self, request, pk=None):
        """Analyze native libraries in APK"""
        scan = self.get_object()
        
        try:
            from androguard.core.apk import APK
            
            apk = APK(scan.file_path.path)
            
            # Extract native libraries
            native_libs = []
            for file_info in apk.get_files():
                if file_info.endswith('.so'):
                    native_libs.append({
                        'name': file_info.split('/')[-1],
                        'path': file_info,
                        'arch': 'armeabi-v7a' if 'armeabi-v7a' in file_info else 
                               'arm64-v8a' if 'arm64-v8a' in file_info else 
                               'x86' if 'x86' in file_info else 'unknown'
                    })
            
            return Response({
                'total_native_libraries': len(native_libs),
                'libraries': native_libs,
                'architectures': list(set(lib['arch'] for lib in native_libs)),
                'risk_level': 'high' if len(native_libs) > 5 else 'medium' if len(native_libs) > 0 else 'low',
                'notes': 'Native libraries may contain more vulnerabilities and are harder to analyze'
            })
        except Exception as e:
            return Response({
                'error': f'Failed to analyze native libraries: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'])
    def resource_analysis(self, request, pk=None):
        """Analyze APK resources and assets"""
        scan = self.get_object()
        
        try:
            from androguard.core.apk import APK
            
            apk = APK(scan.file_path.path)
            
            # Analyze resources
            resources = {
                'layouts': 0,
                'menus': 0,
                'values': 0,
                'drawables': 0,
                'raw': 0,
                'other': 0
            }
            
            suspicious_resources = []
            
            for file_info in apk.get_files():
                lower_file = file_info.lower()
                
                if 'layout' in lower_file:
                    resources['layouts'] += 1
                elif 'menu' in lower_file:
                    resources['menus'] += 1
                elif 'values' in lower_file:
                    resources['values'] += 1
                elif 'drawable' in lower_file:
                    resources['drawables'] += 1
                elif 'raw' in lower_file:
                    resources['raw'] += 1
                    suspicious_resources.append(file_info)
                else:
                    resources['other'] += 1
            
            return Response({
                'resource_counts': resources,
                'total_resources': sum(resources.values()),
                'suspicious_raw_resources': suspicious_resources[:20],
                'timestamp': scan.updated_at
            })
        except Exception as e:
            return Response({
                'error': f'Failed to analyze resources: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'])
    def hardcoded_secrets(self, request, pk=None):
        """Detect hardcoded secrets and credentials"""
        scan = self.get_object()
        
        try:
            from androguard.core.apk import APK
            import re
            
            apk = APK(scan.file_path.path)
            
            secrets = {
                'api_keys': [],
                'aws_keys': [],
                'firebase_urls': [],
                'private_keys': [],
                'tokens': [],
                'urls': []
            }
            
            patterns = {
                'api_keys': re.compile(r'(?i)(api[_-]?key|apikey|secret|token)\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?'),
                'aws_keys': re.compile(r'(?i)(AKIA|aws)[A-Z0-9]{16,}'),
                'firebase': re.compile(r'https://[a-zA-Z0-9\-]+\.firebaseio\.com'),
                'private_keys': re.compile(r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----'),
                'jwt': re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
            }
            
            for dex in apk.get_dex():
                strings = dex.get_strings()
                
                for s in strings[:10000]:
                    if patterns['firebase'].search(s):
                        secrets['firebase_urls'].append(s)
                    if patterns['jwt'].search(s):
                        secrets['tokens'].append(s)
                    if patterns['private_keys'].search(s):
                        secrets['private_keys'].append(s)
            
            return Response({
                'total_secrets_found': sum(len(v) for v in secrets.values() if isinstance(v, list)),
                'secrets': {k: v[:10] for k, v in secrets.items()},  # Limit results
                'risk_level': 'critical' if sum(len(v) for v in secrets.values() if isinstance(v, list)) > 5 else 'high' if sum(len(v) for v in secrets.values() if isinstance(v, list)) > 0 else 'low',
                'timestamp': scan.updated_at
            })
        except Exception as e:
            return Response({
                'error': f'Failed to analyze secrets: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['get'])
    def code_obfuscation(self, request, pk=None):
        """Analyze code obfuscation techniques"""
        scan = self.get_object()
        
        try:
            from androguard.core.apk import APK
            
            apk = APK(scan.file_path.path)
            
            obfuscation_indicators = {
                'suspicious_names': 0,
                'reflection_usage': 0,
                'native_calls': 0,
                'string_encryption': 0,
                'packed_methods': 0
            }
            
            obfuscation_details = []
            
            for dex in apk.get_dex():
                for method in dex.get_methods():
                    method_name = method.get_name()
                    
                    # Check for suspicious class/method names (single letters, etc.)
                    if len(method_name) <= 2 and method_name not in ['<init>', '<clinit>']:
                        obfuscation_indicators['suspicious_names'] += 1
                    
                    # Check for reflection API usage
                    for instr in method.get_instructions():
                        if 'forName' in str(instr) or 'getMethod' in str(instr):
                            obfuscation_indicators['reflection_usage'] += 1
                            obfuscation_details.append(f"Reflection in {method_name}")
            
            return Response({
                'obfuscation_score': min(100, sum(obfuscation_indicators.values()) * 5),
                'indicators': obfuscation_indicators,
                'is_likely_obfuscated': sum(obfuscation_indicators.values()) > 10,
                'details': obfuscation_details[:10],
                'timestamp': scan.updated_at
            })
        except Exception as e:
            return Response({
                'error': f'Failed to analyze obfuscation: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # ── AI-powered security intelligence report ───────────────────────────────

    @action(detail=True, methods=['post'], url_path='ai_analysis')
    def ai_analysis(self, request, pk=None):
        """
        Generate (or regenerate) an AI security intelligence report for a
        completed scan using Google Gemini.

        Returns the structured report and caches it on scan.ai_report so
        subsequent requests can retrieve it without re-calling the API.
        If 'force' is passed as a query param the cache is bypassed.
        """
        scan = self.get_object()

        if scan.status != 'completed':
            return Response(
                {'error': 'AI analysis is only available for completed scans.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Return cached result unless caller requests regeneration
        force = request.query_params.get('force', '').lower() in ('1', 'true', 'yes')
        if scan.ai_report and not force:
            return Response({'report': scan.ai_report, 'cached': True})

        try:
            from .ai_analyzer import generate_ai_report
            report = generate_ai_report(scan)
            scan.ai_report = report
            scan.save(update_fields=['ai_report'])
            return Response({'report': report, 'cached': False})

        except ValueError as e:
            # Missing API key
            return Response(
                {'error': str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            return Response(
                {'error': f'AI analysis failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )