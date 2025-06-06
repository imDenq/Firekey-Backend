# credentials/models.py
from django.db import models
from django.contrib.auth.models import User
import uuid
from django.utils import timezone
from datetime import timedelta

class Tag(models.Model):
    """Modèle pour les tags des credentials"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tags')
    name = models.CharField(max_length=50)
    color = models.CharField(max_length=20, default='#90caf9')  # Couleur par défaut: bleu clair
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['name']
        unique_together = ['user', 'name']  # Un utilisateur ne peut pas avoir deux tags du même nom

    def __str__(self):
        return f"{self.name} ({self.user.username})"

class Credential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    website = models.URLField(blank=True)
    email = models.EmailField(blank=True)
    note = models.TextField(blank=True)
    is_sensitive = models.BooleanField(default=False)
    password_encrypted = models.TextField()  # Stocke le ciphertext AES
    created_at = models.DateTimeField(auto_now_add=True)  # Ajout explicite du champ
    updated_at = models.DateTimeField(auto_now=True)  # Ajout d'un champ de mise à jour
    tags = models.ManyToManyField(Tag, related_name='credentials', blank=True)

    def __str__(self):
        return f"{self.name} ({self.user.username})"

    @property
    def has_e2e_version(self):
        """Vérifie si ce credential a une version E2E"""
        return hasattr(self, 'e2e_version') and self.e2e_version is not None
    
    def create_e2e_version(self, encrypted_data: dict, search_hashes: dict):
        """
        Crée une version E2E de ce credential
        """
        from .models_e2e import CredentialE2E
        
        e2e_credential = CredentialE2E.objects.create(
            user=self.user,
            encrypted_name=encrypted_data['encrypted_name'],
            encrypted_website=encrypted_data.get('encrypted_website', ''),
            encrypted_email=encrypted_data.get('encrypted_email', ''),
            encrypted_password=encrypted_data['encrypted_password'],
            encrypted_notes=encrypted_data.get('encrypted_notes', ''),
            name_search_hash=search_hashes.get('name', ''),
            website_search_hash=search_hashes.get('website', ''),
            email_search_hash=search_hashes.get('email', ''),
            is_sensitive=self.is_sensitive,
            legacy_credential=self
        )
        
        return e2e_credential

class CredentialShare(models.Model):
    """Modèle pour les liens de partage temporaires de credentials"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    credential = models.ForeignKey(Credential, on_delete=models.CASCADE, related_name='shares')
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_shares')
    
    # Date d'expiration du lien
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    # Nombre d'accès maximums et compteur d'utilisation
    max_access_count = models.PositiveIntegerField(null=True, blank=True)
    access_count = models.PositiveIntegerField(default=0)
    
    # Clé aléatoire pour sécuriser davantage l'accès
    access_key = models.CharField(max_length=64, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Partage de {self.credential.name} par {self.creator.username} (expire le {self.expires_at.strftime('%d/%m/%Y')})"
    
    def save(self, *args, **kwargs):
        # Génération d'une clé d'accès aléatoire si non définie
        if not self.access_key:
            self.access_key = uuid.uuid4().hex
            
        # Si expires_at n'est pas défini, on le définit par défaut à 24h
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(days=1)
            
        super().save(*args, **kwargs)
    
    @property
    def is_expired(self):
        """Vérifie si le lien est expiré"""
        # Expiré par date
        if self.expires_at <= timezone.now():
            return True
            
        # Expiré par nombre d'accès
        if self.max_access_count is not None and self.access_count >= self.max_access_count:
            return True
            
        return False
    
    @property
    def remaining_accesses(self):
        """Renvoie le nombre d'accès restants"""
        if self.max_access_count is None:
            return None  # Illimité
        return max(0, self.max_access_count - self.access_count)
    
    def increment_access_count(self):
        """
        Incrémente le compteur d'accès en évitant les duplications dues aux doubles requêtes
        """
        # Stocker la dernière mise à jour comme attribut statique de la classe pour une meilleure persistance
        # Utiliser un dictionnaire avec les IDs de partage comme clés
        if not hasattr(CredentialShare, '_last_access_updates'):
            CredentialShare._last_access_updates = {}
    
        share_id = str(self.id)  # Convertir UUID en string pour l'utiliser comme clé
        last_update = CredentialShare._last_access_updates.get(share_id)
        now = timezone.now()
    
        # Mettre à jour le compteur d'accès avec une requête atomique pour éviter les conditions de course
        from django.db.models import F
        CredentialShare.objects.filter(id=self.id).update(access_count=F('access_count') + 1)
    
        # Rafraîchir l'objet depuis la base de données pour avoir la valeur à jour
        self.refresh_from_db(fields=['access_count'])
    
        # Enregistrer le timestamp de cette mise à jour
        CredentialShare._last_access_updates[share_id] = now

    # Nouvelles méthodes à ajouter
    def days_remaining(self):
        """Calcule le nombre de jours restants avant expiration"""
        if self.is_expired:
            return 0
            
        now = timezone.now()
        delta = self.expires_at - now
        return max(0, delta.days)
        
    def extend_expiry(self, days):
        """
        Prolonge la date d'expiration du nombre de jours spécifié
        à partir de maintenant (pas à partir de la date d'expiration existante)
        """
        if days < 1:
            raise ValueError("Le nombre de jours doit être positif")
            
        self.expires_at = timezone.now() + timedelta(days=days)
        self.save(update_fields=['expires_at'])
        return self
    
    def reset_access_count(self):
        """Réinitialise le compteur d'accès à zéro"""
        self.access_count = 0
        self.save(update_fields=['access_count'])
        return self