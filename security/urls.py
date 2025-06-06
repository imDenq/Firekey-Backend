# security/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import SecurityViewSet
from .api_views import log_audit_event  # importation de la fonction utilitaire

router = DefaultRouter()
router.register(r'security', SecurityViewSet, basename='security')

urlpatterns = [
    path('', include(router.urls)),
    # Route utilitaire pour logger un événement d'audit
    path('log_event/', log_audit_event, name='log-audit-event'),
    
]