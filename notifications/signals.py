# notifications/signals.py - Version corrigée
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.utils import timezone

from accounts.models import UserProfile
from credentials.models import Credential, CredentialShare
from .services import NotificationService

# ============================
# Signaux pour les credentials - MODIFIÉS POUR ÉVITER LES DUPLICATIONS
# ============================

@receiver(post_save, sender=Credential)
def credential_saved(sender, instance, created, **kwargs):
    """
    Déclenche des notifications lors de la création ou 
    modification d'un credential
    """
    # Vérifier si ce signal a déjà été traité par security/signals.py
    signal_source = getattr(instance, '_notification_source', None)
    if signal_source == 'notified':
        return
        
    # Marquer l'instance comme traitée pour éviter les doublons dans d'autres handlers
    instance._notification_source = 'notified'
    
    if created:
        # Création d'un nouveau credential
        NotificationService.credential_created(
            user=instance.user,
            credential_name=instance.name,
            website=instance.website
        )
    else:
        # Mise à jour d'un credential existant (uniquement si ce n'est pas l'unlocked)
        update_fields = kwargs.get('update_fields')
        if update_fields is None or 'unlocked' not in update_fields:
            NotificationService.credential_updated(
                user=instance.user,
                credential_name=instance.name
            )

@receiver(post_delete, sender=Credential)
def credential_deleted(sender, instance, **kwargs):
    """Déclenche une notification lors de la suppression d'un credential"""
    # Vérifier si ce signal a déjà été traité
    signal_source = getattr(instance, '_notification_source', None)
    if signal_source == 'notified':
        return
        
    # Marquer l'instance comme traitée
    instance._notification_source = 'notified'
    
    NotificationService.credential_deleted(
        user=instance.user,
        credential_name=instance.name
    )

# =========================
# Signaux pour les partages - MODIFIÉS
# =========================

@receiver(post_save, sender=CredentialShare)
def share_created(sender, instance, created, **kwargs):
    """Déclenche une notification lors de la création d'un partage"""
    # Vérifier si ce signal a déjà été traité
    signal_source = getattr(instance, '_notification_source', None)
    if signal_source == 'notified':
        return
        
    # Marquer l'instance comme traitée
    instance._notification_source = 'notified'
    
    if created:
        # Calcul du nombre de jours entre maintenant et la date d'expiration
        days_until_expiry = (instance.expires_at - timezone.now()).days + 1
        
        NotificationService.credential_shared(
            user=instance.creator,
            credential_name=instance.credential.name,
            share_id=str(instance.id),
            expiry_days=days_until_expiry,
            access_limit=instance.max_access_count
        )

# ===========================
# Fonctions pour accounts app - PAS MODIFIÉES
# ===========================

def notify_password_changed(user, request=None):
    """
    À appeler manuellement depuis les vues lors du changement de mot de passe
    """
    ip = None
    device_info = None
    
    if request:
        # Tenter d'obtenir l'IP du client
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        # Tenter d'obtenir des infos sur le navigateur/appareil
        device_info = request.META.get('HTTP_USER_AGENT')
    
    NotificationService.password_changed(
        user=user,
        ip_address=ip,
        device_info=device_info
    )

def notify_new_login(user, ip_address=None, location=None, device=None, browser=None):
    """
    À appeler manuellement depuis les vues lors d'une nouvelle connexion
    """
    NotificationService.new_login(
        user=user,
        ip_address=ip_address,
        location=location,
        device_info=device,
        browser=browser
    )

# Signal pour les mises à jour de profil - MODIFIÉ
@receiver(post_save, sender=UserProfile)
def profile_updated(sender, instance, created, **kwargs):
    """Déclenche une notification lors de la mise à jour du profil utilisateur"""
    # Ne rien faire lors de la création initiale du profil
    if created:
        return
        
    # Vérifier si ce signal a déjà été traité
    signal_source = getattr(instance, '_notification_source', None)
    if signal_source == 'notified':
        return
        
    # Marquer l'instance comme traitée
    instance._notification_source = 'notified'

    # Vérifier si update_fields est une liste ou un ensemble avant de vérifier si 'two_factor_enabled' est dedans
    update_fields = kwargs.get('update_fields')
    if update_fields and hasattr(update_fields, '__contains__') and 'two_factor_enabled' in update_fields:
        if instance.two_factor_enabled:
            NotificationService.two_factor_enabled(
                user=instance.user,
                method="app"
            )
        else:
            NotificationService.two_factor_disabled(
                user=instance.user
            )
    else:
        # Mise à jour générale du profil
        # Éviter de créer trop de notifications inutiles
        pass  # Désactivé temporairement

# ===================================================
# Fonction pour notifier de l'accès à un credential partagé
# ===================================================

def notify_shared_credential_accessed(share, request=None):
    """
    À appeler manuellement depuis la vue access_shared_credential
    quand quelqu'un accède à un credential partagé
    """
    ip = None
    location = "Localisation inconnue"
    
    if request:
        # Obtenir l'IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
            
        # En production, on pourrait utiliser un service de géolocalisation
        # pour obtenir la localisation à partir de l'IP
        # location = get_location_from_ip(ip)
    
    NotificationService.credential_accessed(
        user=share.creator,
        credential_name=share.credential.name,
        share_id=str(share.id),
        accessed_by_ip=ip,
        location=location
    )

# ===================================================
# Système pour générer des notifications initiales
# ===================================================

def create_welcome_notification(user):
    """Crée une notification de bienvenue pour les nouveaux utilisateurs"""
    NotificationService.create_notification(
        user=user,
        type='welcome',
        level='success',
        title="Bienvenue sur FireKey",
        message="Merci d'avoir choisi FireKey pour sécuriser vos mots de passe. "
                "Notre système est conçu pour vous offrir la meilleure protection possible. "
                "N'hésitez pas à explorer toutes les fonctionnalités!",
        requires_action=False
    )
    
    # Notification de sécurité pour encourager l'activation de la 2FA
    NotificationService.create_notification(
        user=user,
        type='security_recommendation',
        level='warning',
        title="Renforcez votre sécurité avec la 2FA",
        message="Pour une sécurité optimale, nous vous recommandons d'activer "
                "l'authentification à deux facteurs (2FA). Cette fonctionnalité "
                "ajoute une couche de protection supplémentaire à votre compte.",
        requires_action=True,
        action_url="/profile"
    )

# Créer une notification de bienvenue pour les nouveaux utilisateurs
@receiver(post_save, sender=User)
def user_created(sender, instance, created, **kwargs):
    """Déclenche des notifications lors de la création d'un utilisateur"""
    if created:
        create_welcome_notification(instance)