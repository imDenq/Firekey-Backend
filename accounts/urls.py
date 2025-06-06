# accounts/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    TwoFactorAuthView,
    register_view,
    protected_view,
    CustomTokenObtainPairView,
    UserViewSet,
    confirm_delete_account
)
from rest_framework_simplejwt.views import TokenRefreshView

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='users')

urlpatterns = [
    path('register/', register_view, name='register'),
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('protected/', protected_view, name='protected'),
    path('two-factor-auth/', TwoFactorAuthView.as_view(), name='two-factor-auth'),
    path('users/e2e_status/', UserViewSet.as_view({'get': 'e2e_status'}), name='e2e_status'),

    # Routes pour la sécurité
    path('users/change-password/', UserViewSet.as_view({'post': 'change_password'}), name='change_password'),
    path('users/sessions/', UserViewSet.as_view({
        'get': 'sessions',
        'delete': 'sessions'
    }), name='sessions'),
    path('users/two-factor/', UserViewSet.as_view({
        'get': 'two_factor',
        'post': 'two_factor'
    }), name='two_factor'),
    path('users/delete-account/', UserViewSet.as_view({
        'post': 'delete_account'
    }), name='delete_account'),
    
    # Route pour la confirmation de suppression (sans authentification)
    path('confirm-delete-account/', confirm_delete_account, name='confirm_delete_account'),

    # URLs générées par le router
    path('', include(router.urls)),
]