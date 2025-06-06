from django.db import models
from django.contrib.auth.models import User
import uuid
from django.utils import timezone

class UserKeyDerivation(models.Model):
    """
    Stocke les paramètres de dérivation de clé pour chaque utilisateur
    Ne stocke JAMAIS la clé elle-même
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='key_derivation')
    salt = models.CharField(max_length=128)  # Salt pour dérivation PBKDF2
    iterations = models.IntegerField(default=100000)
    algorithm = models.CharField(max_length=50, default='PBKDF2-SHA256')
    search_salt = models.CharField(max_length=128)  # Salt pour hashs de recherche
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Dérivation de clé pour {self.user.username}"

class CredentialE2E(models.Model):
    """
    Modèle pour credentials chiffrés de bout en bout
    Coexiste avec le modèle Credential existant
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='e2e_credentials')
    
    # Toutes les données sensibles sont chiffrées côté client
    encrypted_name = models.TextField()
    encrypted_website = models.TextField(blank=True)
    encrypted_email = models.TextField(blank=True)
    encrypted_password = models.TextField()
    encrypted_notes = models.TextField(blank=True)
    
    # Métadonnées de chiffrement
    encryption_version = models.CharField(max_length=10, default='1.0')
    algorithm = models.CharField(max_length=50, default='AES-256-GCM')
    
    # Hashs pour recherche (générés côté client, non réversibles)
    name_search_hash = models.CharField(max_length=64, db_index=True, blank=True)
    website_search_hash = models.CharField(max_length=64, db_index=True, blank=True)
    email_search_hash = models.CharField(max_length=64, db_index=True, blank=True)
    
    # Métadonnées non sensibles
    is_sensitive = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Relation avec l'ancien modèle pour migration
    legacy_credential = models.OneToOneField(
        'Credential', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='e2e_version'
    )
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'name_search_hash']),
            models.Index(fields=['user', 'website_search_hash']),
            models.Index(fields=['user', 'created_at']),
        ]
    
    def __str__(self):
        return f"Credential E2E {self.id} pour {self.user.username}"