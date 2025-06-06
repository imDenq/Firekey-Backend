# notifications/views.py
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.utils import timezone

from .models import Notification, NotificationPreference
from .serializers import (
    NotificationSerializer, 
    NotificationPreferenceSerializer,
    UpdateNotificationSettingsSerializer
)
from .services import NotificationService

class NotificationViewSet(viewsets.ModelViewSet):
    """ViewSet pour gérer les notifications de l'utilisateur connecté"""
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Ne récupère que les notifications de l'utilisateur connecté"""
        return Notification.objects.filter(user=self.request.user)
    
    def list(self, request, *args, **kwargs):
        """
        Renvoie la liste des notifications avec pagination
        Accepte le paramètre ?unread=true pour filtrer les notifications non lues
        """
        # Filtre pour les notifications non lues
        unread_only = request.query_params.get('unread', 'false').lower() == 'true'
        queryset = self.get_queryset()
        
        if unread_only:
            queryset = queryset.filter(read=False)
        
        # Pagination standard de DRF
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['POST'])
    def mark_as_read(self, request, pk=None):
        """Marque une notification spécifique comme lue"""
        notification = self.get_object()
        notification.mark_as_read()
        return Response({'status': 'success'}, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['POST'])
    def mark_all_as_read(self, request):
        """Marque toutes les notifications de l'utilisateur comme lues"""
        count = NotificationService.mark_all_as_read(request.user)
        return Response({
            'status': 'success',
            'count': count
        }, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['GET'])
    def unread_count(self, request):
        """Renvoie le nombre de notifications non lues pour l'utilisateur"""
        count = NotificationService.get_unread_count(request.user)
        return Response({'count': count}, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['DELETE'])
    def clear_all(self, request):
        """Supprime toutes les notifications lues de l'utilisateur"""
        # Ne supprime que les notifications déjà lues
        count, _ = Notification.objects.filter(user=request.user, read=True).delete()
        return Response({
            'status': 'success',
            'count': count
        }, status=status.HTTP_200_OK)

class NotificationPreferenceViewSet(viewsets.ModelViewSet):
    """ViewSet pour gérer les préférences de notification de l'utilisateur"""
    serializer_class = NotificationPreferenceSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Ne récupère que les préférences de l'utilisateur connecté"""
        return NotificationPreference.objects.filter(user=self.request.user)
    
    def list(self, request, *args, **kwargs):
        """Renvoie les préférences de l'utilisateur connecté"""
        # Récupérer ou créer les préférences de l'utilisateur
        preferences, created = NotificationPreference.objects.get_or_create(user=request.user)
        serializer = self.get_serializer(preferences)
        return Response(serializer.data)
    
    @action(detail=False, methods=['PATCH'])
    def update_settings(self, request):
        """
        Met à jour les préférences de notification
        Permet la mise à jour partielle des préférences
        """
        serializer = UpdateNotificationSettingsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Récupérer ou créer les préférences
        preferences, created = NotificationPreference.objects.get_or_create(user=request.user)
        
        # Mettre à jour les préférences générales
        data = serializer.validated_data
        
        # Traiter les champs directs
        for field in ['email_notifications', 'security_alerts', 'product_updates', 'marketing_emails', 'email_digest_frequency']:
            if field in data:
                setattr(preferences, field, data[field])
        
        # Traiter les préférences par type de notification
        if 'notification_types' in data:
            current_settings = preferences.notification_settings.copy() if preferences.notification_settings else {}
            # Mettre à jour uniquement les types fournis
            for notification_type, enabled in data['notification_types'].items():
                current_settings[notification_type] = enabled
            preferences.notification_settings = current_settings
        
        preferences.save()
        
        # Renvoyer les préférences mises à jour
        serializer = self.get_serializer(preferences)
        return Response(serializer.data)

# Pour des tests de démonstration rapides
from django.http import JsonResponse
from .models import NotificationType, NotificationLevel

def create_test_notification(request):
    """
    Vue de test pour créer une notification d'exemple
    À retirer ou protéger en production
    """
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentification requise'}, status=401)
    
    notification_type = request.GET.get('type', NotificationType.SYSTEM_UPDATE)
    
    # Exemple de métadonnées pour différents types
    metadata = None
    if notification_type == NotificationType.SYSTEM_UPDATE:
        metadata = {
            'version': '2.1.0',
            'features': [
                'Nouveau système de notifications',
                'Amélioration de la sécurité',
                'Corrections de bugs'
            ]
        }
    
    # Créer une notification de test
    notification = NotificationService.create_notification(
        user=request.user,
        type=notification_type,
        level=NotificationLevel.INFO,
        title="Notification de test",
        message="Ceci est une notification de test générée manuellement.",
        metadata=metadata
    )
    
    # Serializer pour l'affichage
    from .serializers import NotificationSerializer
    serializer = NotificationSerializer(notification)
    
    return JsonResponse(serializer.data)