# importexport/models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class ImportHistory(models.Model):
    """Modèle pour suivre l'historique des imports"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='import_history')
    source = models.CharField(max_length=50, help_text="Source de l'import (ex: google, lastpass, csv)")
    file_name = models.CharField(max_length=255, blank=True, null=True)
    credentials_imported = models.IntegerField(default=0)
    credentials_skipped = models.IntegerField(default=0)
    credentials_merged = models.IntegerField(default=0)
    status = models.CharField(max_length=20, default='success', 
                               choices=[('success', 'Réussi'), ('error', 'Échoué'), ('partial', 'Partiellement réussi')])
    error_message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Historique d'import"
        verbose_name_plural = "Historiques d'imports"
    
    def __str__(self):
        return f"Import {self.source} par {self.user.username} le {self.created_at.strftime('%d/%m/%Y')}"

class ExportHistory(models.Model):
    """Modèle pour suivre l'historique des exports"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='export_history')
    format = models.CharField(max_length=50, help_text="Format de l'export (ex: firekey, csv, json)")
    encrypted = models.BooleanField(default=True)
    credentials_exported = models.IntegerField(default=0)
    status = models.CharField(max_length=20, default='success', 
                               choices=[('success', 'Réussi'), ('error', 'Échoué')])
    error_message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Historique d'export"
        verbose_name_plural = "Historiques d'exports"
    
    def __str__(self):
        return f"Export {self.format} par {self.user.username} le {self.created_at.strftime('%d/%m/%Y')}"

# Modèle pour stocker temporairement les métadonnées des fichiers téléchargés
# pour les analyses de securité avant import
class ImportFileStatus(models.Model):
    """Stockage temporaire des analyses de fichier d'import"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='import_file_status')
    file_id = models.CharField(max_length=64, unique=True)  # Identifiant unique du fichier
    source = models.CharField(max_length=50)
    file_name = models.CharField(max_length=255)
    analysis_status = models.CharField(max_length=20, default='pending',
                                       choices=[('pending', 'En attente'), 
                                                ('analyzing', 'En cours d\'analyse'),
                                                ('ready', 'Prêt'), 
                                                ('error', 'Erreur')])
    total_credentials = models.IntegerField(default=0)
    new_credentials = models.IntegerField(default=0)
    duplicate_credentials = models.IntegerField(default=0)
    conflict_credentials = models.IntegerField(default=0)
    error_message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Analyse de {self.file_name} ({self.source}) - {self.analysis_status}"
    
    def save(self, *args, **kwargs):
        # Définir l'expiration à 1 heure par défaut
        if not self.expires_at or self.expires_at <= timezone.now():
            self.expires_at = timezone.now() + timezone.timedelta(hours=1)
        super().save(*args, **kwargs)
    
    @property
    def is_expired(self):
        return timezone.now() >= self.expires_at