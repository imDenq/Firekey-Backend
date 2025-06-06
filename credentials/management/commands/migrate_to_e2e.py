from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from credentials.models import Credential
from credentials.models_e2e import CredentialE2E, UserKeyDerivation

class Command(BaseCommand):
    help = 'Prépare la migration vers le chiffrement E2E'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Affiche ce qui sera fait sans effectuer les changements',
        )
    
    def handle(self, *args, **options):
        dry_run = options['dry_run']
        
        if dry_run:
            self.stdout.write(self.style.WARNING('Mode dry-run activé - aucune modification ne sera effectuée'))
        
        # Créer les paramètres de dérivation pour tous les utilisateurs
        users_without_derivation = User.objects.filter(key_derivation__isnull=True)
        
        self.stdout.write(f'Utilisateurs nécessitant des paramètres de dérivation: {users_without_derivation.count()}')
        
        if not dry_run:
            for user in users_without_derivation:
                UserKeyDerivation.objects.create(user=user)
                self.stdout.write(f'Paramètres créés pour {user.username}')
        
        # Statistiques sur les credentials existants
        total_credentials = Credential.objects.count()
        e2e_credentials = CredentialE2E.objects.count()
        
        self.stdout.write(f'Credentials existants: {total_credentials}')
        self.stdout.write(f'Credentials E2E: {e2e_credentials}')
        self.stdout.write(f'Migration nécessaire pour: {total_credentials - e2e_credentials} credentials')