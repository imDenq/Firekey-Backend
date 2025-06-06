# importexport/tasks.py
import logging
from celery import shared_task
from django.utils import timezone
from .temp_file_manager import temp_file_manager
from .models import ImportFileStatus

logger = logging.getLogger(__name__)

@shared_task
def cleanup_expired_temp_files():
    """
    Tâche Celery pour nettoyer automatiquement les fichiers temporaires expirés.
    À exécuter toutes les heures.
    """
    try:
        logger.info("Début du nettoyage des fichiers temporaires expirés")
        
        # Nettoyer les fichiers sur le disque (1 heure d'âge max)
        deleted_files = temp_file_manager.cleanup_expired_files(max_age_hours=1)
        
        # Nettoyer aussi les enregistrements de statut expirés en base
        expired_statuses = ImportFileStatus.objects.filter(
            expires_at__lt=timezone.now()
        )
        
        deleted_statuses = 0
        for status in expired_statuses:
            # S'assurer que le fichier associé est aussi supprimé
            temp_file_manager.delete_file(status.file_id)
            deleted_statuses += 1
        
        # Supprimer les enregistrements expirés
        expired_statuses.delete()
        
        logger.info(f"Nettoyage terminé: {deleted_files} fichiers, {deleted_statuses} statuts supprimés")
        
        return {
            'success': True,
            'deleted_files': deleted_files,
            'deleted_statuses': deleted_statuses
        }
        
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage automatique: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

@shared_task  
def cleanup_orphaned_temp_files():
    """
    Nettoie les fichiers temporaires orphelins (sans enregistrement en base).
    À exécuter une fois par jour.
    """
    try:
        logger.info("Début du nettoyage des fichiers orphelins")
        
        # Récupérer tous les file_ids en base
        db_file_ids = set(ImportFileStatus.objects.values_list('file_id', flat=True))
        
        # Récupérer tous les fichiers sur disque
        import os
        from django.conf import settings
        
        temp_dir = temp_file_manager.temp_dir
        disk_file_ids = set()
        
        if os.path.exists(temp_dir):
            for filename in os.listdir(temp_dir):
                if filename.endswith('.enc'):
                    file_id = filename[:-4]  # Enlever l'extension .enc
                    disk_file_ids.add(file_id)
        
        # Identifier les fichiers orphelins (sur disque mais pas en base)
        orphaned_files = disk_file_ids - db_file_ids
        
        deleted_count = 0
        for file_id in orphaned_files:
            try:
                temp_file_manager.delete_file(file_id)
                deleted_count += 1
                logger.info(f"Fichier orphelin supprimé: {file_id}")
            except Exception as e:
                logger.warning(f"Erreur lors de la suppression du fichier orphelin {file_id}: {str(e)}")
        
        logger.info(f"Nettoyage des orphelins terminé: {deleted_count} fichiers supprimés")
        
        return {
            'success': True,
            'deleted_orphans': deleted_count
        }
        
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage des orphelins: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }