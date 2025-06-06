# importexport/management/commands/cleanup_temp_files.py
import os
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from importexport.temp_file_manager import temp_file_manager
from importexport.models import ImportFileStatus

class Command(BaseCommand):
    help = 'Nettoie les fichiers temporaires d\'import expirés'

    def add_arguments(self, parser):
        parser.add_argument(
            '--max-age',
            type=int,
            default=1,
            help='Âge maximum en heures avant suppression (défaut: 1)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Affiche ce qui serait supprimé sans vraiment supprimer'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force la suppression même des fichiers récents'
        )

    def handle(self, *args, **options):
        max_age_hours = options['max_age']
        dry_run = options['dry_run']
        force = options['force']
        
        self.stdout.write(
            self.style.SUCCESS(f'Début du nettoyage des fichiers temporaires')
        )
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING('Mode DRY-RUN: Aucun fichier ne sera supprimé')
            )
        
        try:
            # 1. Nettoyer les fichiers sur disque
            if not dry_run:
                deleted_files = temp_file_manager.cleanup_expired_files(max_age_hours)
            else:
                # Mode dry-run: compter les fichiers qui seraient supprimés
                deleted_files = self._count_expired_files(max_age_hours)
            
            self.stdout.write(
                f'Fichiers temporaires: {deleted_files} fichier(s) {"supprimé(s)" if not dry_run else "à supprimer"}'
            )
            
            # 2. Nettoyer les enregistrements en base
            cutoff_time = timezone.now() - timezone.timedelta(hours=max_age_hours)
            expired_statuses = ImportFileStatus.objects.filter(
                expires_at__lt=cutoff_time if not force else timezone.now()
            )
            
            status_count = expired_statuses.count()
            
            if not dry_run:
                # Supprimer les fichiers associés
                for status in expired_statuses:
                    temp_file_manager.delete_file(status.file_id)
                
                # Supprimer les enregistrements
                expired_statuses.delete()
            
            self.stdout.write(
                f'Enregistrements de statut: {status_count} enregistrement(s) {"supprimé(s)" if not dry_run else "à supprimer"}'
            )
            
            # 3. Nettoyer les fichiers orphelins
            orphaned_count = self._cleanup_orphaned_files(dry_run)
            self.stdout.write(
                f'Fichiers orphelins: {orphaned_count} fichier(s) {"supprimé(s)" if not dry_run else "à supprimer"}'
            )
            
            # Résumé final
            total = deleted_files + status_count + orphaned_count
            if total == 0:
                self.stdout.write(
                    self.style.SUCCESS('Aucun fichier à nettoyer. Système propre !')
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Nettoyage terminé: {total} élément(s) {"supprimé(s)" if not dry_run else "à supprimer"}'
                    )
                )
            
        except Exception as e:
            raise CommandError(f'Erreur lors du nettoyage: {str(e)}')
    
    def _count_expired_files(self, max_age_hours):
        """Compte les fichiers expirés sans les supprimer"""
        try:
            cutoff_time = timezone.now() - timezone.timedelta(hours=max_age_hours)
            count = 0
            
            temp_dir = temp_file_manager.temp_dir
            if not os.path.exists(temp_dir):
                return 0
            
            for filename in os.listdir(temp_dir):
                if not filename.endswith('.enc'):
                    continue
                
                file_path = os.path.join(temp_dir, filename)
                try:
                    file_mtime = timezone.datetime.fromtimestamp(os.path.getmtime(file_path))
                    file_mtime = timezone.make_aware(file_mtime)
                    
                    if file_mtime < cutoff_time:
                        count += 1
                except Exception:
                    continue
            
            return count
            
        except Exception:
            return 0
    
    def _cleanup_orphaned_files(self, dry_run=False):
        """Nettoie les fichiers orphelins"""
        try:
            db_file_ids = set(ImportFileStatus.objects.values_list('file_id', flat=True))
            
            temp_dir = temp_file_manager.temp_dir
            disk_file_ids = set()
            
            if os.path.exists(temp_dir):
                for filename in os.listdir(temp_dir):
                    if filename.endswith('.enc'):
                        file_id = filename[:-4]
                        disk_file_ids.add(file_id)
            
            orphaned_files = disk_file_ids - db_file_ids
            
            if not dry_run:
                for file_id in orphaned_files:
                    try:
                        temp_file_manager.delete_file(file_id)
                    except Exception:
                        continue
            
            return len(orphaned_files)
            
        except Exception:
            return 0