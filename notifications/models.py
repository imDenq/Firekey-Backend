# notifications/models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _

class NotificationType(models.TextChoices):
    """Types de notifications supportés par le système"""
    PASSWORD_CHANGED = 'password_changed', _('Mot de passe modifié')
    NEW_LOGIN = 'new_login', _('Nouvelle connexion')
    CREDENTIAL_SHARED = 'credential_shared', _('Credential partagé')
    CREDENTIAL_ACCESS = 'credential_access', _('Accès à un credential partagé')
    CREDENTIAL_CREATED = 'credential_created', _('Nouveau credential créé')
    CREDENTIAL_UPDATED = 'credential_updated', _('Credential mis à jour')
    CREDENTIAL_DELETED = 'credential_deleted', _('Credential supprimé')
    SECURITY_ALERT = 'security_alert', _('Alerte de sécurité')
    ACCOUNT_UPDATED = 'account_updated', _('Profil mis à jour')
    SYSTEM_UPDATE = 'system_update', _('Mise à jour système')
    TWO_FACTOR_ENABLED = 'two_factor_enabled', _('2FA activée')
    TWO_FACTOR_DISABLED = 'two_factor_disabled', _('2FA désactivée')

class NotificationLevel(models.TextChoices):
    """Niveaux d'importance des notifications"""
    INFO = 'info', _('Information')
    SUCCESS = 'success', _('Succès')
    WARNING = 'warning', _('Avertissement')
    ERROR = 'error', _('Erreur')

class Notification(models.Model):
    """Modèle principal pour les notifications utilisateur"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    type = models.CharField(max_length=50, choices=NotificationType.choices)
    level = models.CharField(max_length=20, choices=NotificationLevel.choices, default=NotificationLevel.INFO)
    title = models.CharField(max_length=255)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)
    
    # Informations contextuelles (stockées en JSON)
    related_object_id = models.IntegerField(null=True, blank=True)
    related_object_type = models.CharField(max_length=50, null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    
    # Options utilisateur
    requires_action = models.BooleanField(default=False)  # Si une action est requise de l'utilisateur
    action_url = models.CharField(max_length=255, null=True, blank=True)  # URL pour l'action
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'read', 'created_at']),
            models.Index(fields=['type']),
        ]
    
    def __str__(self):
        return f"{self.get_type_display()} - {self.user.username} - {self.created_at.strftime('%d/%m/%Y %H:%M')}"
    
    def mark_as_read(self):
        """Marque la notification comme lue"""
        if not self.read:
            from django.utils import timezone
            self.read = True
            self.read_at = timezone.now()
            self.save(update_fields=['read', 'read_at'])

class NotificationPreference(models.Model):
    """Préférences de notifications pour chaque utilisateur"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='notification_preferences')
    email_notifications = models.BooleanField(default=True)
    security_alerts = models.BooleanField(default=True)
    product_updates = models.BooleanField(default=True)
    marketing_emails = models.BooleanField(default=False)
    
    # Fréquence des emails de résumé
    EMAIL_FREQUENCY_CHOICES = [
        ('daily', _('Quotidien')),
        ('weekly', _('Hebdomadaire')),
        ('monthly', _('Mensuel')),
        ('never', _('Jamais')),
    ]
    email_digest_frequency = models.CharField(
        max_length=10,
        choices=EMAIL_FREQUENCY_CHOICES,
        default='weekly'
    )
    
    # Préférences par type de notification
    notification_settings = models.JSONField(default=dict, blank=True)
    
    def __str__(self):
        return f"Préférences de {self.user.username}"
    
    def get_notification_setting(self, notification_type):
        """
        Obtient les préférences pour un type de notification donné.
        Retourne True par défaut si non spécifié.
        """
        settings = self.notification_settings
        return settings.get(notification_type, True)
    
    def update_notification_setting(self, notification_type, enabled):
        """Met à jour un paramètre de notification spécifique"""
        settings = self.notification_settings.copy()
        settings[notification_type] = enabled
        self.notification_settings = settings
        self.save(update_fields=['notification_settings'])

# Signaux pour créer automatiquement des préférences par défaut
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def create_notification_preferences(sender, instance, created, **kwargs):
    """Crée des préférences de notification par défaut pour les nouveaux utilisateurs"""
    if created:
        try:
            if hasattr(instance, '_state') and not instance._state.adding:
                return
                
            NotificationPreference.objects.get_or_create(user=instance)
        except Exception as e:
            print(f"Erreur lors de la création des préférences de notification: {e}")
            pass
