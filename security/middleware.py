# security/middleware.py
from django.utils.deprecation import MiddlewareMixin

class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Middleware pour attacher la requête HTTP actuelle aux objets 
    modèles créés ou modifiés pendant cette requête.
    Cela permet aux signaux de post_save d'accéder aux informations
    de la requête comme l'IP client, le User-Agent, etc.
    """
    
    def process_request(self, request):
        """Stocke la requête dans le thread local"""
        # Si l'utilisateur est authentifié, attachez la requête à l'utilisateur
        if hasattr(request, 'user') and request.user.is_authenticated:
            request.user._request = request
            
    def process_response(self, request, response):
        """Nettoie la requête stockée après son traitement"""
        if hasattr(request, 'user') and request.user.is_authenticated:
            if hasattr(request.user, '_request'):
                delattr(request.user, '_request')
        return response