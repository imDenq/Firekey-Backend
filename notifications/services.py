# notifications/services.py
from django.contrib.auth.models import User
from django.utils import timezone
from .models import Notification, NotificationType, NotificationLevel, NotificationPreference

class NotificationService:
    """
    Service centralisé pour la gestion des notifications
    Fournit des méthodes pour créer différents types de notifications
    """
    
    @staticmethod
    def create_notification(
        user, 
        type, 
        level=NotificationLevel.INFO, 
        title=None, 
        message=None, 
        requires_action=False,
        action_url=None,
        related_object_id=None,
        related_object_type=None,
        metadata=None
    ):
        """
        Méthode générique pour créer une notification
        Vérifie d'abord les préférences de l'utilisateur
        """
        # Vérifier si l'utilisateur souhaite recevoir ce type de notification
        try:
            preferences = NotificationPreference.objects.get(user=user)
            if not preferences.get_notification_setting(type):
                return None  # L'utilisateur a désactivé ce type de notification
        except NotificationPreference.DoesNotExist:
            # Créer des préférences par défaut si non existantes
            preferences = NotificationPreference.objects.create(user=user)
        
        # Titre par défaut basé sur le type si non fourni
        if title is None:
            # Utiliser l'affichage du choix comme titre par défaut
            for choice in NotificationType.choices:
                if choice[0] == type:
                    title = choice[1]
                    break
        
        # Créer la notification
        return Notification.objects.create(
            user=user,
            type=type,
            level=level,
            title=title,
            message=message or "",
            requires_action=requires_action,
            action_url=action_url,
            related_object_id=related_object_id,
            related_object_type=related_object_type,
            metadata=metadata or {}
        )
    
    @staticmethod
    def password_changed(user, ip_address=None, device_info=None):
        """Notification de changement de mot de passe"""
        metadata = {
            'ip_address': ip_address,
            'device_info': device_info
        }
        
        message = "Votre mot de passe a été modifié avec succès."
        if ip_address:
            message += f" Changement effectué depuis l'adresse IP: {ip_address}"
        
        return NotificationService.create_notification(
            user=user,
            type=NotificationType.PASSWORD_CHANGED,
            level=NotificationLevel.SUCCESS,
            title="Mot de passe modifié",
            message=message,
            metadata=metadata
        )
    
    @staticmethod
    def new_login(user, ip_address=None, location=None, device_info=None, browser=None):
        """Notification de nouvelle connexion"""
        metadata = {
            'ip_address': ip_address,
            'location': location,
            'device_info': device_info,
            'browser': browser
        }
        
        location_str = location or "Localisation inconnue"
        device_str = device_info or "Appareil inconnu"
        browser_str = browser or "Navigateur inconnu"
        
        message = f"Nouvelle connexion détectée depuis {location_str} sur {device_str} ({browser_str})."
        
        return NotificationService.create_notification(
            user=user,
            type=NotificationType.NEW_LOGIN,
            level=NotificationLevel.INFO,
            title="Nouvelle connexion",
            message=message,
            metadata=metadata
        )
    
    @staticmethod
    def credential_shared(user, credential_name, share_id, expiry_days, access_limit=None):
        """Notification de partage d'un credential"""
        metadata = {
            'credential_name': credential_name,
            'share_id': share_id,
            'expiry_days': expiry_days,
            'access_limit': access_limit
        }
        
        expiry_msg = f"Le lien expirera dans {expiry_days} jour{'s' if expiry_days > 1 else ''}."
        access_msg = ""
        if access_limit:
            access_msg = f" Limité à {access_limit} accès."
        
        message = f"Vous avez partagé le credential '{credential_name}'. {expiry_msg}{access_msg}"
        
        return NotificationService.create_notification(
            user=user,
            type=NotificationType.CREDENTIAL_SHARED,
            level=NotificationLevel.INFO,
            title="Credential partagé",
            message=message,
            metadata=metadata
        )
    
    @staticmethod
    def credential_accessed(user, credential_name, share_id, accessed_by_ip=None, location=None):
        """Notification d'accès à un credential partagé"""
        metadata = {
            'credential_name': credential_name,
            'share_id': share_id,
            'accessed_by_ip': accessed_by_ip,
            'location': location,
            'access_time': timezone.now().isoformat()
        }
        
        location_str = location or "Localisation inconnue"
        message = f"Votre credential partagé '{credential_name}' a été consulté depuis {location_str}."
        
        return NotificationService.create_notification(
            user=user,
            type=NotificationType.CREDENTIAL_ACCESS,
            level=NotificationLevel.INFO,
            title="Credential consulté",
            message=message,
            metadata=metadata
        )
    
    @staticmethod
    def credential_created(user, credential_name, website=None):
        """Notification de création d'un nouveau credential"""
        metadata = {
            'credential_name': credential_name,
            'website': website
        }
        
        website_str = f" pour {website}" if website else ""
        message = f"Vous avez créé un nouveau credential '{credential_name}'{website_str}."
        
        return NotificationService.create_notification(
            user=user,
            type=NotificationType.CREDENTIAL_CREATED,
            level=NotificationLevel.SUCCESS,
            title="Nouveau credential créé",
            message=message,
            metadata=metadata
        )
    
    @staticmethod
    def credential_updated(user, credential_name, updated_fields=None):
        """Notification de mise à jour d'un credential"""
        metadata = {
            'credential_name': credential_name,
            'updated_fields': updated_fields or []
        }
        
        fields_str = ""
        if updated_fields:
            fields_list = ', '.join(updated_fields)
            fields_str = f" Champs mis à jour: {fields_list}"
        
        message = f"Votre credential '{credential_name}' a été mis à jour.{fields_str}"
        
        return NotificationService.create_notification(
            user=user,
            type=NotificationType.CREDENTIAL_UPDATED,
            level=NotificationLevel.INFO,
            title="Credential mis à jour",
            message=message,
            metadata=metadata
        )
    
    @staticmethod
    def credential_deleted(user, credential_name):
        """Notification de suppression d'un credential"""
        metadata = {
            'credential_name': credential_name,
            'deleted_at': timezone.now().isoformat()
        }
        
        message = f"Votre credential '{credential_name}' a été supprimé."
        
        return NotificationService.create_notification(
            user=user,
            type=NotificationType.CREDENTIAL_DELETED,
            level=NotificationLevel.WARNING,
            title="Credential supprimé",
            message=message,
            metadata=metadata
        )
    
    @staticmethod
    def security_alert(user, alert_type, message, severity="high"):
        """Notification d'alerte de sécurité"""
        metadata = {
            'alert_type': alert_type,
            'severity': severity
        }
        
        return NotificationService.create_notification(
            user=user,
            type=NotificationType.SECURITY_ALERT,
            level=NotificationLevel.ERROR if severity == "high" else NotificationLevel.WARNING,
            title="Alerte de sécurité",
            message=message,
            requires_action=True,
            action_url="/profile",  # Rediriger vers les paramètres de sécurité
            metadata=metadata
        )
    
    @staticmethod
    def account_updated(user, updated_fields=None):
        """Notification de mise à jour de profil"""
        metadata = {
            'updated_fields': updated_fields or []
        }
        
        fields_str = ""
        if updated_fields:
            fields_list = ', '.join(updated_fields)
            fields_str = f" Champs mis à jour: {fields_list}"
        
        message = f"Votre profil a été mis à jour.{fields_str}"
        
        return NotificationService.create_notification(
            user=user,
            type=NotificationType.ACCOUNT_UPDATED,
            level=NotificationLevel.SUCCESS,
            title="Profil mis à jour",
            message=message,
            metadata=metadata
        )
    
    @staticmethod
    def system_update(user, version=None, features=None):
        """Notification de mise à jour système"""
        metadata = {
            'version': version,
            'features': features
        }
        
        version_str = f" vers la version {version}" if version else ""
        message = f"FireKey a été mis à jour{version_str}."
        
        if features:
            feature_list = "\n• " + "\n• ".join(features)
            message += f"\nNouvelles fonctionnalités:{feature_list}"
        
        return NotificationService.create_notification(
            user=user,
            type=NotificationType.SYSTEM_UPDATE,
            level=NotificationLevel.INFO,
            title="Mise à jour du système",
            message=message,
            metadata=metadata
        )
    
    @staticmethod
    def two_factor_enabled(user, method="app"):
        """Notification d'activation de l'authentification à deux facteurs"""
        metadata = {
            'method': method
        }
        
        message = f"L'authentification à deux facteurs a été activée sur votre compte via {method}."
        
        return NotificationService.create_notification(
            user=user,
            type=NotificationType.TWO_FACTOR_ENABLED,
            level=NotificationLevel.SUCCESS,
            title="2FA activée",
            message=message,
            metadata=metadata
        )
    
    @staticmethod
    def two_factor_disabled(user):
        """Notification de désactivation de l'authentification à deux facteurs"""
        message = "L'authentification à deux facteurs a été désactivée sur votre compte."
        
        return NotificationService.create_notification(
            user=user,
            type=NotificationType.TWO_FACTOR_DISABLED,
            level=NotificationLevel.WARNING,
            title="2FA désactivée",
            message=message
        )
    
    @staticmethod
    def get_unread_count(user):
        """Obtient le nombre de notifications non lues pour un utilisateur"""
        return Notification.objects.filter(user=user, read=False).count()
    
    @staticmethod
    def mark_all_as_read(user):
        """Marque toutes les notifications d'un utilisateur comme lues"""
        now = timezone.now()
        return Notification.objects.filter(user=user, read=False).update(read=True, read_at=now)
    
    @staticmethod
    def clear_old_notifications(days=30):
        """Supprime les notifications plus anciennes qu'un certain nombre de jours"""
        cutoff_date = timezone.now() - timezone.timedelta(days=days)
        return Notification.objects.filter(created_at__lt=cutoff_date).delete()