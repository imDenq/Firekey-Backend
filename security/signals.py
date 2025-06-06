# security/signals.py - Version corrigée
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import User

from credentials.models import Credential, CredentialShare
from accounts.models import UserProfile
from .models import AuditLogEntry

def get_client_ip(request):
    """Récupère l'adresse IP du client à partir de la requête"""
    if not request:
        return None
        
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_device_info(request):
    """Récupère les informations sur l'appareil à partir de la requête"""
    if not request:
        return ""
        
    return request.META.get('HTTP_USER_AGENT', "")

# Signal pour les credentials - MODIFIÉ POUR ÉVITER LES DUPLICATIONS
@receiver(post_save, sender=Credential)
def credential_saved(sender, instance, created, **kwargs):
    """Enregistre une entrée de journal quand un credential est créé ou modifié"""
    # Récupérer le contexte qui identifie l'origine du signal
    signal_source = getattr(instance, '_signal_source', None)
    
    # Si ce signal a déjà été traité par une autre fonction, on sort
    if signal_source == 'audit_logged':
        return
        
    request = getattr(instance, '_request', None)
    
    if created:
        action_type = 'credential_create'
        action_detail = f"Création du credential '{instance.name}'"
    else:
        # Vérifier si c'est juste un changement de l'état déverrouillé
        update_fields = kwargs.get('update_fields')
        if update_fields and len(update_fields) == 1 and 'unlocked' in update_fields:
            # Ne pas enregistrer les changements d'état de déverrouillage
            return
            
        action_type = 'credential_update'
        action_detail = f"Mise à jour du credential '{instance.name}'"
    
    # Marquer l'instance comme traitée pour éviter les doublons
    instance._signal_source = 'audit_logged'
    
    # Créer l'entrée d'audit
    AuditLogEntry.objects.create(
        user=instance.user,
        action_type=action_type,
        action_detail=action_detail,
        ip_address=get_client_ip(request),
        device_info=get_device_info(request),
        related_object_id=instance.id
    )

@receiver(post_delete, sender=Credential)
def credential_deleted(sender, instance, **kwargs):
    """Enregistre une entrée de journal quand un credential est supprimé"""
    # Récupérer le contexte qui identifie l'origine du signal
    signal_source = getattr(instance, '_signal_source', None)
    
    # Si ce signal a déjà été traité par une autre fonction, on sort
    if signal_source == 'audit_logged':
        return
        
    request = getattr(instance, '_request', None)
    
    # Marquer l'instance comme traitée
    instance._signal_source = 'audit_logged'
    
    AuditLogEntry.objects.create(
        user=instance.user,
        action_type='credential_delete',
        action_detail=f"Suppression du credential '{instance.name}'",
        ip_address=get_client_ip(request),
        device_info=get_device_info(request),
        related_object_id=instance.id
    )

# Signal pour les partages - MODIFIÉ
@receiver(post_save, sender=CredentialShare)
def share_saved(sender, instance, created, **kwargs):
    """Enregistre une entrée de journal quand un partage est créé ou modifié"""
    # Éviter les doublons
    signal_source = getattr(instance, '_signal_source', None)
    if signal_source == 'audit_logged':
        return
        
    request = getattr(instance, '_request', None)
    
    if created:
        action_type = 'share_create'
        action_detail = f"Création d'un partage pour '{instance.credential.name}'"
    else:
        action_type = 'share_update'
        action_detail = f"Mise à jour du partage pour '{instance.credential.name}'"
    
    # Convertir l'UUID en string pour éviter l'erreur d'integer
    related_object_id = str(instance.id)
    
    # Marquer l'instance comme traitée
    instance._signal_source = 'audit_logged'
    
    # Créer l'entrée de journal
    AuditLogEntry.objects.create(
        user=instance.creator,
        action_type=action_type,
        action_detail=action_detail,
        ip_address=get_client_ip(request),
        device_info=get_device_info(request),
        related_object_id=None  # Mettre à None au lieu de l'UUID
    )

@receiver(post_delete, sender=CredentialShare)
def share_deleted(sender, instance, **kwargs):
    """Enregistre une entrée de journal quand un partage est supprimé"""
    # Éviter les doublons
    signal_source = getattr(instance, '_signal_source', None)
    if signal_source == 'audit_logged':
        return
        
    request = getattr(instance, '_request', None)
    
    # Marquer l'instance comme traitée
    instance._signal_source = 'audit_logged'
    
    AuditLogEntry.objects.create(
        user=instance.creator,
        action_type='share_delete',
        action_detail=f"Suppression du partage pour '{instance.credential.name}'",
        ip_address=get_client_ip(request),
        device_info=get_device_info(request),
        related_object_id=instance.id
    )

# Signal pour les mises à jour de profil - MODIFIÉ
@receiver(post_save, sender=UserProfile)
def profile_updated(sender, instance, created, **kwargs):
    """Enregistre une entrée de journal quand un profil est mis à jour"""
    # Éviter les doublons
    signal_source = getattr(instance, '_signal_source', None)
    if signal_source == 'audit_logged' or created:
        # Ne rien faire lors de la création du profil ou si déjà traité
        return
        
    request = getattr(instance, '_request', None)
    
    # Marquer l'instance comme traitée 
    instance._signal_source = 'audit_logged'
    
    # Vérifier si c'est un changement de 2FA
    update_fields = kwargs.get('update_fields')
    if update_fields and 'two_factor_enabled' in update_fields:
        if instance.two_factor_enabled:
            action_type = '2fa_enable'
            action_detail = "Activation de l'authentification à deux facteurs"
        else:
            action_type = '2fa_disable'
            action_detail = "Désactivation de l'authentification à deux facteurs"
    else:
        action_type = 'profile_update'
        action_detail = "Mise à jour du profil utilisateur"
    
    AuditLogEntry.objects.create(
        user=instance.user,
        action_type=action_type,
        action_detail=action_detail,
        ip_address=get_client_ip(request),
        device_info=get_device_info(request)
    )