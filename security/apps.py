# security/apps.py
from django.apps import AppConfig

class SecurityConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'security'
    
    def ready(self):
        """
        Initialisation des signaux de l'application - modifiée pour éviter les doublons
        """
        # Importer les signaux uniquement au démarrage de l'application
        import security.signals

class NotificationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'notifications'

    def ready(self):
        """
        Initialisation des signaux de l'application - modifiée pour éviter les doublons
        """
        # Importer les signaux uniquement au démarrage de l'application
        import notifications.signals