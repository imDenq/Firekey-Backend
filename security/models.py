# security/models.py
from django.db import models
from django.contrib.auth.models import User
from credentials.models import Credential

class PasswordStrength(models.TextChoices):
    """Niveaux de force d'un mot de passe"""
    WEAK = 'weak', 'Faible'
    MEDIUM = 'medium', 'Moyen'
    STRONG = 'strong', 'Fort'

class SecurityAudit(models.Model):
    """
    Modèle pour stocker les audits de sécurité des utilisateurs
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='security_audits')
    created_at = models.DateTimeField(auto_now_add=True)
    security_score = models.IntegerField(default=0)
    weak_passwords_count = models.IntegerField(default=0)
    duplicate_passwords_count = models.IntegerField(default=0)
    old_passwords_count = models.IntegerField(default=0)
    total_credentials_count = models.IntegerField(default=0)
    
    # Résumé JSON des problèmes détectés
    audit_details = models.JSONField(default=dict)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Audit de sécurité de {self.user.username} le {self.created_at.strftime('%d/%m/%Y')}"

class CredentialStrengthCache(models.Model):
    """
    Cache de la force des mots de passe pour éviter de recalculer à chaque fois
    """
    credential = models.OneToOneField(Credential, on_delete=models.CASCADE, related_name='strength_cache')
    strength = models.CharField(
        max_length=10, 
        choices=PasswordStrength.choices,
        default=PasswordStrength.MEDIUM
    )
    score = models.IntegerField(default=50)  # Score numérique de 0 à 100
    last_updated = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Force du mot de passe pour {self.credential.name}"

class AuditLogEntry(models.Model):
    """
    Journaux d'activité pour l'utilisateur
    """
    ACTION_TYPES = [
        ('login', 'Connexion'),
        ('logout', 'Déconnexion'),
        ('credential_create', 'Création de credential'),
        ('credential_update', 'Mise à jour de credential'),
        ('credential_delete', 'Suppression de credential'),
        ('credential_view', 'Consultation de credential'),
        ('credential_create_e2e', 'Création de credential E2E'),
        ('share_create', 'Création de partage'),
        ('share_access', 'Accès à un partage'),
        ('share_delete', 'Suppression de partage'),
        ('profile_update', 'Mise à jour du profil'),
        ('password_change', 'Changement de mot de passe'),
        ('security_audit', 'Audit de sécurité'),
        ('2fa_enable', 'Activation 2FA'),
        ('2fa_disable', 'Désactivation 2FA'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='audit_logs')
    action_type = models.CharField(max_length=50, choices=ACTION_TYPES)
    action_detail = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_info = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    related_object_id = models.TextField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['action_type']),
        ]
    
    def __str__(self):
        return f"{self.get_action_type_display()} par {self.user.username} le {self.created_at.strftime('%d/%m/%Y %H:%M')}"