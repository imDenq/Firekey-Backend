# notifications/serializers.py
from rest_framework import serializers
from .models import Notification, NotificationPreference

class NotificationSerializer(serializers.ModelSerializer):
    """Serializer pour le modèle Notification"""
    type_display = serializers.CharField(source='get_type_display', read_only=True)
    level_display = serializers.CharField(source='get_level_display', read_only=True)
    relative_time = serializers.SerializerMethodField()
    
    class Meta:
        model = Notification
        fields = [
            'id', 'type', 'type_display', 'level', 'level_display',
            'title', 'message', 'created_at', 'read', 'read_at',
            'requires_action', 'action_url', 'relative_time',
            'related_object_id', 'related_object_type', 'metadata'
        ]
        read_only_fields = ['id', 'created_at', 'read_at']
    
    def get_relative_time(self, obj):
        """Calcule une description relative du temps écoulé depuis la création"""
        from django.utils import timezone
        from datetime import timedelta
        
        now = timezone.now()
        diff = now - obj.created_at
        
        if diff < timedelta(minutes=1):
            return "à l'instant"
        elif diff < timedelta(hours=1):
            minutes = diff.seconds // 60
            return f"il y a {minutes} minute{'s' if minutes > 1 else ''}"
        elif diff < timedelta(days=1):
            hours = diff.seconds // 3600
            return f"il y a {hours} heure{'s' if hours > 1 else ''}"
        elif diff < timedelta(days=7):
            days = diff.days
            return f"il y a {days} jour{'s' if days > 1 else ''}"
        elif diff < timedelta(days=30):
            weeks = diff.days // 7
            return f"il y a {weeks} semaine{'s' if weeks > 1 else ''}"
        else:
            return obj.created_at.strftime('%d/%m/%Y')

class NotificationPreferenceSerializer(serializers.ModelSerializer):
    """Serializer pour les préférences de notification"""
    class Meta:
        model = NotificationPreference
        fields = [
            'id', 'email_notifications', 'security_alerts',
            'product_updates', 'marketing_emails',
            'email_digest_frequency', 'notification_settings'
        ]
        read_only_fields = ['id']

class UpdateNotificationSettingsSerializer(serializers.Serializer):
    """
    Serializer pour la mise à jour des préférences de notification
    Permet de mettre à jour plusieurs paramètres à la fois
    """
    email_notifications = serializers.BooleanField(required=False)
    security_alerts = serializers.BooleanField(required=False)
    product_updates = serializers.BooleanField(required=False)
    marketing_emails = serializers.BooleanField(required=False)
    email_digest_frequency = serializers.ChoiceField(
        choices=NotificationPreference.EMAIL_FREQUENCY_CHOICES,
        required=False
    )
    notification_types = serializers.DictField(
        child=serializers.BooleanField(),
        required=False
    )