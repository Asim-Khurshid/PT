from rest_framework import serializers
from .models import Scan, Vulnerability, Permission, Report

class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = ['id', 'title', 'description', 'severity', 'category', 'file_path', 'line_number', 'remediation', 'created_at']

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'permission_name', 'is_dangerous', 'description']

class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ['id', 'summary', 'recommendations', 'pdf_url', 'json_url', 'created_at']

class ScanSerializer(serializers.ModelSerializer):
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    permissions = PermissionSerializer(many=True, read_only=True)
    report = ReportSerializer(read_only=True)

    class Meta:
        model = Scan
        fields = ['id', 'app_name', 'package_name', 'file_name', 'file_size', 'version', 
                  'threat_level', 'threat_score', 'total_issues', 'critical_issues', 'high_issues', 
                  'medium_issues', 'low_issues', 'status', 'vulnerabilities', 'permissions', 'report',
              'hash_md5', 'hash_sha256', 'static_analysis', 'static_analysis_enabled', 'dynamic_analysis', 'dynamic_analysis_enabled',
              'fuzzing_analysis', 'fuzzing_enabled', 'ai_analysis_enabled',
              'started_at', 'completed_at', 'created_at', 'updated_at']
        read_only_fields = ['hash_md5', 'hash_sha256', 'threat_score', 'vulnerabilities', 'permissions', 'report', 'static_analysis', 'dynamic_analysis', 'fuzzing_analysis']

class ScanCreateSerializer(serializers.ModelSerializer):
    package_name = serializers.CharField(required=False, allow_blank=True)
    static_analysis_enabled = serializers.BooleanField(required=False, default=True)
    dynamic_analysis_enabled = serializers.BooleanField(required=False, default=False)
    fuzzing_enabled = serializers.BooleanField(required=False, default=False)
    ai_analysis_enabled = serializers.BooleanField(required=False, default=False)

    class Meta:
        model = Scan
        fields = ['file_path', 'app_name', 'package_name', 'version', 'static_analysis_enabled', 'dynamic_analysis_enabled', 'fuzzing_enabled', 'ai_analysis_enabled']
