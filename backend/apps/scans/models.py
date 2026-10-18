from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
import os

class Scan(models.Model):
    THREAT_LEVEL_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('safe', 'Safe'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('scanning', 'Scanning'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans')
    app_name = models.CharField(max_length=255)
    package_name = models.CharField(max_length=255)
    file_name = models.CharField(max_length=255)
    file_path = models.FileField(upload_to='apks/')
    file_size = models.BigIntegerField()
    version = models.CharField(max_length=50, blank=True)
    
    threat_level = models.CharField(max_length=20, choices=THREAT_LEVEL_CHOICES, default='safe')
    threat_score = models.IntegerField(default=0)
    total_issues = models.IntegerField(default=0)
    critical_issues = models.IntegerField(default=0)
    high_issues = models.IntegerField(default=0)
    medium_issues = models.IntegerField(default=0)
    low_issues = models.IntegerField(default=0)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    error_message = models.TextField(blank=True, null=True)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    hash_md5 = models.CharField(max_length=32, null=True, blank=True)
    hash_sha256 = models.CharField(max_length=64, null=True, blank=True)
    
    # Static Analysis Artifacts (MobSF-style comprehensive data)
    static_analysis = models.JSONField(null=True, blank=True, default=dict)
    static_analysis_enabled = models.BooleanField(default=True)
    # Dynamic Analysis Results (ADB-based emulator/device run)
    dynamic_analysis = models.JSONField(null=True, blank=True, default=dict)
    dynamic_analysis_enabled = models.BooleanField(default=False)
    # API Fuzzing Results (endpoint vulnerability testing)
    fuzzing_analysis = models.JSONField(null=True, blank=True, default=dict)
    fuzzing_enabled = models.BooleanField(default=False)
    ai_analysis_enabled = models.BooleanField(default=False)
    
    # Additional analysis features
    certificate_info = models.JSONField(null=True, blank=True, default=dict)
    strings_analysis = models.JSONField(null=True, blank=True, default=dict)
    entropy_analysis = models.JSONField(null=True, blank=True, default=dict)

    # AI-generated security intelligence report (cached after first generation)
    ai_report = models.JSONField(null=True, blank=True, default=None)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'scans'
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(fields=['user', 'hash_md5'], name='unique_user_apk')
        ]

    def __str__(self):
        return f"{self.app_name} - {self.threat_level}"
    
    def _delete_media_files(self):
        """Delete all media files associated with this scan."""
        # 1. Delete APK file
        if self.file_path:
            try:
                apk_path = self.file_path.path
                if os.path.exists(apk_path):
                    os.remove(apk_path)
            except Exception as e:
                print(f"Warning: Failed to delete APK file: {e}")

        # 2. Delete PCAP file (absolute path stored in dynamic_analysis JSON)
        dynamic = self.dynamic_analysis or {}
        network = dynamic.get('network_capture', {}) or {}
        pcap_path = network.get('local_pcap')
        if pcap_path and os.path.isfile(pcap_path):
            try:
                os.remove(pcap_path)
            except Exception as e:
                print(f"Warning: Failed to delete PCAP file {pcap_path}: {e}")

        # 3. Delete screenshot files (absolute paths stored in dynamic_analysis JSON)
        screenshots = dynamic.get('screenshots', []) or []
        for shot in screenshots:
            if shot and os.path.isfile(shot):
                try:
                    os.remove(shot)
                except Exception as e:
                    print(f"Warning: Failed to delete screenshot {shot}: {e}")

        # 4. Delete PDF report file (relative path stored in Report.pdf_url as "reports/<filename>")
        try:
            report = self.report
            if report.pdf_url:
                pdf_abs = os.path.join(settings.MEDIA_ROOT, report.pdf_url)
                if os.path.isfile(pdf_abs):
                    try:
                        os.remove(pdf_abs)
                    except Exception as e:
                        print(f"Warning: Failed to delete PDF report {pdf_abs}: {e}")
        except Exception:
            pass  # No report associated

    def delete(self, *args, **kwargs):
        """Override delete to also remove all associated media files from storage."""
        self._delete_media_files()
        super().delete(*args, **kwargs)

class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    category = models.CharField(max_length=100)
    file_path = models.CharField(max_length=500, blank=True)
    line_number = models.IntegerField(null=True, blank=True)
    remediation = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'vulnerabilities'
        ordering = ['-severity', '-created_at']

    def __str__(self):
        return f"{self.scan.app_name} - {self.title}"

class Permission(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='permissions')
    permission_name = models.CharField(max_length=255)
    is_dangerous = models.BooleanField(default=False)
    description = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'permissions'

    def __str__(self):
        return f"{self.scan.app_name} - {self.permission_name}"

class Report(models.Model):
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name='report')
    summary = models.TextField()
    recommendations = models.TextField()
    pdf_url = models.CharField(max_length=1000, blank=True, null=True)
    json_url = models.TextField(blank=True, null=True)  # Changed to TextField for unlimited size
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'reports'

    def __str__(self):
        return f"Report - {self.scan.app_name}"

    def delete(self, *args, **kwargs):
        """Override delete to also remove the PDF report file from storage."""
        if self.pdf_url:
            pdf_abs = os.path.join(settings.MEDIA_ROOT, self.pdf_url)
            if os.path.isfile(pdf_abs):
                try:
                    os.remove(pdf_abs)
                except Exception as e:
                    print(f"Warning: Failed to delete PDF report {pdf_abs}: {e}")
        super().delete(*args, **kwargs)
