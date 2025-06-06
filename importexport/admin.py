# importexport/admin.py
from django.contrib import admin
from .models import ImportHistory, ExportHistory, ImportFileStatus

@admin.register(ImportHistory)
class ImportHistoryAdmin(admin.ModelAdmin):
    list_display = ('user', 'source', 'credentials_imported', 'credentials_merged', 
                   'credentials_skipped', 'status', 'created_at')
    list_filter = ('source', 'status', 'created_at')
    search_fields = ('user__username', 'file_name')
    readonly_fields = ('created_at',)
    date_hierarchy = 'created_at'

@admin.register(ExportHistory)
class ExportHistoryAdmin(admin.ModelAdmin):
    list_display = ('user', 'format', 'encrypted', 'credentials_exported', 
                   'status', 'created_at')
    list_filter = ('format', 'encrypted', 'status', 'created_at')
    search_fields = ('user__username',)
    readonly_fields = ('created_at',)
    date_hierarchy = 'created_at'

@admin.register(ImportFileStatus)
class ImportFileStatusAdmin(admin.ModelAdmin):
    list_display = ('user', 'file_name', 'source', 'analysis_status', 
                   'total_credentials', 'created_at', 'expires_at')
    list_filter = ('source', 'analysis_status', 'created_at')
    search_fields = ('user__username', 'file_name', 'file_id')
    readonly_fields = ('created_at', 'updated_at')
    date_hierarchy = 'created_at'