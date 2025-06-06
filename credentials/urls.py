# credentials/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CredentialViewSet, CredentialShareViewSet, access_shared_credential, TagViewSet, CredentialE2EViewSet, UserKeyDerivationViewSet

router = DefaultRouter()
router.register(r'credentials', CredentialViewSet, basename='credentials')
router.register(r'shares', CredentialShareViewSet, basename='credential-shares')
router.register(r'tags', TagViewSet, basename='tags')
router.register(r'credentials-e2e', CredentialE2EViewSet, basename='credentials-e2e')
router.register(r'key-derivation', UserKeyDerivationViewSet, basename='key-derivation')

urlpatterns = [
    path('', include(router.urls)),
    # Endpoint API pour accéder aux données d'un credential partagé
    path('share/<uuid:share_id>/<str:access_key>/', access_shared_credential, name='access-shared-credential'),
    
    # URLs explicites pour les opérations sur les partages 
    # (ces routes sont déjà gérées par le routeur, mais on les liste pour clarté)
    path('shares/', CredentialShareViewSet.as_view({'get': 'list', 'post': 'create'}), name='shares-list'),
    path('shares/<uuid:pk>/', CredentialShareViewSet.as_view({
        'get': 'retrieve', 
        'patch': 'partial_update', 
        'delete': 'destroy'
    }), name='shares-detail'),
]