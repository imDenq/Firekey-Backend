from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import NotificationViewSet, NotificationPreferenceViewSet, create_test_notification

router = DefaultRouter()
router.register(r'notifications', NotificationViewSet, basename='notifications')
router.register(r'preferences', NotificationPreferenceViewSet, basename='notification-preferences')

urlpatterns = [
    path('', include(router.urls)),
    path('test-notification/', create_test_notification, name='test-notification'),
]