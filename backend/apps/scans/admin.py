from django.contrib import admin
from .models import Scan, Vulnerability, Permission, Report

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ['app_name', 'user', 'threat_level', 'status', 'created_at']
    search_fields = ['app_name', 'package_name', 'user__username']
    list_filter = ['threat_level', 'status', 'created_at']

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ['title', 'scan', 'severity', 'created_at']
    search_fields = ['title', 'scan__app_name']
    list_filter = ['severity', 'created_at']

@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ['permission_name', 'scan', 'is_dangerous']
    search_fields = ['permission_name', 'scan__app_name']

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['scan', 'created_at']
    search_fields = ['scan__app_name']
