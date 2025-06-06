# importexport/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ImportHistoryViewSet,
    ExportHistoryViewSet,
    FileUploadView,
    ImportPreviewView,
    ImportExecuteView,
    ExportCredentialsView,
    get_import_export_options
)

router = DefaultRouter()
router.register(r'import-history', ImportHistoryViewSet, basename='import-history')
router.register(r'export-history', ExportHistoryViewSet, basename='export-history')

urlpatterns = [
    path('', include(router.urls)),
    
    # Options d'import/export
    path('options/', get_import_export_options, name='import-export-options'),
    
    # Import
    path('upload/', FileUploadView.as_view(), name='file-upload'),
    path('preview/<str:file_id>/', ImportPreviewView.as_view(), name='import-preview'),
    path('import/', ImportExecuteView.as_view(), name='import-execute'),
    
    # Export
    path('export/', ExportCredentialsView.as_view(), name='export-credentials'),
]