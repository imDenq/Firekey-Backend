from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication

class AuthRequiredMiddleware:
    """
    Middleware qui bloque l'accès aux endpoints commençant par /protected/ si l'authentification JWT n'est pas valide.
    Ce middleware utilise explicitement la classe JWTAuthentication pour authentifier la requête.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith('/protected/'):
            jwt_auth = JWTAuthentication()
            try:
                # Tente d'authentifier la requête à l'aide du token JWT transmis dans l'en-tête Authorization
                auth_result = jwt_auth.authenticate(request)
                if auth_result is not None:
                    # Si l'authentification est réussie, on assigne l'utilisateur et le token à la requête
                    request.user, request.auth = auth_result
                else:
                    return JsonResponse({'error': 'Authentification requise.'}, status=401)
            except Exception:
                return JsonResponse({'error': 'Authentification requise.'}, status=401)
        # Procède normalement si la route n'est pas protégée ou si l'authentification est validée
        response = self.get_response(request)
        return response
