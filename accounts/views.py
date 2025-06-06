# accounts/views.py
from datetime import timedelta
import json
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import viewsets, status, serializers
from rest_framework.views import APIView
from .serializers import (
    TwoFactorAuthSerializer,
    UserSerializer, 
    ChangePasswordSerializer,
    UserSessionSerializer, 
    TwoFactorSetupSerializer,
    TwoFactorLoginSerializer,
    DeleteAccountSerializer
)
from .models import UserProfile, UserSession, DeleteAccountToken
import os
from django.conf import settings
from django.db import transaction

# Importation pour parser le User-Agent
from user_agents import parse

# Importation pour déterminer la localisation par IP
import requests

@csrf_exempt
@api_view(['GET'])
@permission_classes([AllowAny])
def confirm_delete_account(request):
    """
    GET /auth/confirm-delete-account/?token=xxx => Confirmer suppression avec token
    Cette approche évite les problèmes d'authentification lors de la suppression
    """
    token_str = request.query_params.get('token')
    if not token_str:
        return Response({"error": "Token requis"}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        token = DeleteAccountToken.objects.get(token=token_str)
        
        if not token.is_valid:
            return Response({"error": "Token expiré"}, status=status.HTTP_400_BAD_REQUEST)
        
        user = token.user
        user_id = user.id
        username = user.username
        
        # Désactiver temporairement les signaux pour éviter les conflits
        from django.db.models.signals import post_save, post_delete, pre_delete
        from django.dispatch import receiver
        
        # Utiliser une transaction pour garantir la cohérence
        with transaction.atomic():
            print(f"Début de la suppression du compte utilisateur: {username} (ID: {user_id})")
            
            # 1. Supprimer les notifications et préférences
            try:
                from notifications.models import NotificationPreference, Notification
                print("Suppression des préférences de notification...")
                NotificationPreference.objects.filter(user=user).delete()
                print("Suppression des notifications...")
                Notification.objects.filter(user=user).delete()
                print("Notifications supprimées avec succès")
            except ImportError:
                print("Module notifications non disponible")
            except Exception as e:
                print(f"Erreur lors de la suppression des notifications: {e}")
            
            # 2. Supprimer les sessions utilisateur
            try:
                print("Suppression des sessions utilisateur...")
                UserSession.objects.filter(user=user).delete()
                print("Sessions supprimées avec succès")
            except Exception as e:
                print(f"Erreur lors de la suppression des sessions: {e}")
            
            # 3. Supprimer les credentials et partages
            try:
                from credentials.models import Credential, CredentialShare
                print("Suppression des partages de credentials...")
                CredentialShare.objects.filter(creator=user).delete()
                print("Suppression des credentials...")
                Credential.objects.filter(user=user).delete()
                print("Credentials supprimés avec succès")
            except ImportError:
                print("Module credentials non disponible")
            except Exception as e:
                print(f"Erreur lors de la suppression des credentials: {e}")
            
            # 4. Supprimer les logs de sécurité
            try:
                from security.models import AuditLog, SecurityIncident
                print("Suppression des logs d'audit...")
                AuditLog.objects.filter(user=user).delete()
                print("Suppression des incidents de sécurité...")
                SecurityIncident.objects.filter(user=user).delete()
                print("Logs de sécurité supprimés avec succès")
            except ImportError:
                print("Module security non disponible")
            except Exception as e:
                print(f"Erreur lors de la suppression des logs de sécurité: {e}")
            
            # 5. Supprimer le profil utilisateur
            try:
                print("Suppression du profil utilisateur...")
                if hasattr(user, 'profile'):
                    user.profile.delete()
                print("Profil utilisateur supprimé avec succès")
            except Exception as e:
                print(f"Erreur lors de la suppression du profil: {e}")
            
            # 6. Supprimer le token de suppression
            try:
                print("Suppression du token de suppression...")
                token.delete()
                print("Token supprimé avec succès")
            except Exception as e:
                print(f"Erreur lors de la suppression du token: {e}")
            
            # 7. Enfin, supprimer l'utilisateur
            print("Suppression de l'utilisateur...")
            user.delete()
            print(f"Utilisateur {username} supprimé avec succès")
        
        print(f"Compte utilisateur supprimé avec succès: ID={user_id}, Username={username}")
        
        return Response({
            "detail": "Compte supprimé avec succès"
        }, status=status.HTTP_200_OK)
        
    except DeleteAccountToken.DoesNotExist:
        return Response({"error": "Token invalide"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        print(f"Erreur lors de la suppression du compte: {str(e)}")
        import traceback
        traceback.print_exc()
        return Response({
            "error": f"Une erreur inattendue s'est produite: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def protected_view(request):
    return Response({'message': f'Hello {request.user.username}, vous êtes authentifié !'}, status=200)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
    hash_algo = request.data.get('hashAlgorithm', 'default')

    if not username or not password:
        return Response({'error': 'username et password requis.'}, status=400)

    if User.objects.filter(username=username).exists():
        return Response({'error': 'Cet utilisateur existe déjà.'}, status=400)

    # Choix de l'algo
    if hash_algo == 'bcrypt':
        # alias interne Django : 'bcrypt_sha256'
        hashed_password = make_password(password, hasher='bcrypt_sha256')
    elif hash_algo == 'argon2':
        hashed_password = make_password(password, hasher='argon2')
    elif hash_algo == 'scrypt':
        hashed_password = make_password(password, hasher='scrypt')
    elif hash_algo == 'pbkdf2':
        hashed_password = make_password(password, hasher='pbkdf2_sha256')
    elif hash_algo == 'pbkdf2sha1':
        hashed_password = make_password(password, hasher='pbkdf2_sha1')
    else:
        # 'default' => utilise l'ordre dans PASSWORD_HASHERS
        hashed_password = make_password(password)

    user = User(username=username, email=email)
    user.password = hashed_password
    user.save()

    return Response({'message': 'Utilisateur créé avec succès.'}, status=201)


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Personnalise la durée de vie du token en fonction de la valeur 'remember' envoyée.
    Gère aussi l'authentification à deux facteurs.
    """
    def validate(self, attrs):
        # Vérifier si l'authentification à deux facteurs est requise
        username = attrs.get('username')
        password = attrs.get('password')
        code = attrs.get('code')  # Ne pas utiliser pop() ici
        
        print(f"DEBUG: Login attempt - Username: {username}, 2FA Code present: {code is not None}")
        if code:
            print(f"DEBUG: Code received: '{code}', type: {type(code)}")
        
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise serializers.ValidationError({'username': 'Utilisateur non trouvé'})
        
        if not user.check_password(password):
            raise serializers.ValidationError({'password': 'Mot de passe incorrect'})
        
        # Vérifier si l'utilisateur a activé l'authentification à deux facteurs
        has_2fa = hasattr(user, 'profile') and user.profile.two_factor_enabled
        
        if has_2fa:
            print(f"DEBUG: User has 2FA enabled, code provided: {code}")
            # Si 2FA est activé, on vérifie le code
            if not code:
                # Ne pas authentifier, mais indiquer que 2FA est nécessaire
                return {
                    'require_2fa': True,
                    'username': username,
                    'message': 'Un code d\'authentification est requis'
                }
            
            # Vérifier le code 2FA
            try:
                code_valid = user.profile.verify_2fa_code(code)
                print(f"DEBUG: 2FA code verification result: {code_valid}")
                
                if not code_valid:
                    return {
                        'require_2fa': True,
                        'username': username,
                        'message': 'Code d\'authentification invalide',
                        'error': 'Code invalide'
                    }
            except Exception as e:
                print(f"DEBUG: Error during 2FA validation: {str(e)}")
                return {
                    'require_2fa': True,
                    'username': username,
                    'message': f'Erreur lors de la vérification du code: {str(e)}',
                    'error': 'Erreur de vérification'
                }
        
        # Vérifier si l'authentification à deux facteurs est requise
        self.user = user
        
        # Créer une copie des attributs sans le code pour la validation JWT
        validated_attrs = attrs.copy()
        if 'code' in validated_attrs:
            print(f"DEBUG: Removing 'code' from validated_attrs for JWT validation")
            validated_attrs.pop('code')  # Supprimer le code s'il existe
        
        try:
            print("DEBUG: Attempting to generate tokens")
            data = super().validate(validated_attrs)
            print("DEBUG: Tokens generated successfully")
        except Exception as e:
            print(f"DEBUG: Error during token generation: {str(e)}")
            # Générer manuellement un nouveau token
            refresh = RefreshToken.for_user(user)
            data = {
                'refresh': str(refresh),
                'access': str(refresh.access_token)
            }
            print("DEBUG: Manual token generation successful")
        
        request = self.context.get('request')
        if request:
            remember = request.data.get('remember', 'false')

            # Si remember = true, on modifie la durée de validité du token
            if remember == 'true':
                refresh = RefreshToken(data['refresh'])
                # Prolonger l'expiration, ex: 7 jours
                refresh.set_exp(lifetime=timedelta(days=7))
                data['refresh'] = str(refresh)
                data['access'] = str(refresh.access_token)
            
            # Enregistrer la session de l'utilisateur
            self._create_user_session(request)
        
        return data
    
    def _create_user_session(self, request):
        """Crée une entrée de session pour l'utilisateur"""
        ip_address = self._get_client_ip(request)
        user_agent_string = request.META.get('HTTP_USER_AGENT', '')
        
        # Parser le User-Agent
        user_agent = parse(user_agent_string)
        browser = f"{user_agent.browser.family} {user_agent.browser.version_string}"
        device = f"{user_agent.device.brand} {user_agent.device.model}" if user_agent.device.brand else user_agent.os.family
        
        # Essayer de déterminer la location basée sur l'IP
        location = self._get_location_from_ip(ip_address)
        
        # Désactiver l'attribut is_current pour toutes les sessions existantes de l'utilisateur
        UserSession.objects.filter(user=self.user, is_current=True).update(is_current=False)
        
        # Créer une nouvelle session
        UserSession.objects.create(
            user=self.user,
            ip_address=ip_address,
            user_agent=user_agent_string,
            location=location,
            device=device,
            browser=browser,
            is_current=True
        )
        
        # Créer une notification de nouvelle connexion
        try:
            from notifications.signals import notify_new_login
            notify_new_login(
                user=self.user,
                ip_address=ip_address,
                location=location,
                device=device,
                browser=browser
            )
        except ImportError:
            # Si le module de notifications n'est pas disponible, on continue sans erreur
            pass
    
    def _get_client_ip(self, request):
        """Récupère l'adresse IP du client"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _get_location_from_ip(self, ip):
        """Essaie de déterminer la localisation à partir de l'adresse IP"""
        try:
            # Utilisation d'un service gratuit de géolocalisation IP
            response = requests.get(f'https://ipapi.co/{ip}/json/')
            if response.status_code == 200:
                data = response.json()
                city = data.get('city', '')
                country = data.get('country_name', '')
                if city and country:
                    return f"{city}, {country}"
                elif country:
                    return country
        except Exception:
            pass
        return "Localisation inconnue"

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Filtre pour ne renvoyer que l'utilisateur connecté
        return User.objects.filter(id=self.request.user.id)

    @action(detail=False, methods=['GET', 'PATCH'])
    def me(self, request):
        """
        GET /auth/users/me/ => Récupérer infos user + profile
        PATCH /auth/users/me/ => Mettre à jour user + profile
        """
        if request.method == 'GET':
            serializer = self.get_serializer(request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            # PATCH - Ajout de logs de débogage
            print("PATCH /auth/users/me/ - Données reçues:", request.data)
        
            # Vérifier si le profil existe
            try:
                profile = request.user.profile
                print("Profil trouvé pour l'utilisateur:", profile)
            except Exception as e:
                print(f"Erreur lors de l'accès au profil: {str(e)}")
                # Si le profil n'existe pas, on le crée
                from .models import UserProfile
                UserProfile.objects.create(user=request.user)
                print("Profil créé pour l'utilisateur")
                
                # Récupérer le profil créé pour pouvoir l'attacher à la requête
                profile = request.user.profile
        
            partial = True
            serializer = self.get_serializer(request.user, data=request.data, partial=partial)
        
            # Vérifier les erreurs de validation
            if not serializer.is_valid():
                print("Erreurs de validation:", serializer.errors)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            # Attacher la requête au profil pour les signaux
            # Cela permettra de récupérer l'IP dans les signaux
            profile._request = request
            
            # Mettre à jour les attributs modifiés
            modified_fields = []
            
            # Traiter les modifications du profil manuellement pour éviter les sauvegardes en cascade
            profile_data = request.data.get('profile', {})
            if profile_data:
                if 'fullName' in profile_data and profile.fullName != profile_data.get('fullName', ''):
                    profile.fullName = profile_data.get('fullName', '')
                    modified_fields.append('fullName')
                    
                if 'language' in profile_data and profile.language != profile_data.get('language', 'Français'):
                    profile.language = profile_data.get('language', 'Français')
                    modified_fields.append('language')
                    
                if 'two_factor_enabled' in profile_data and profile.two_factor_enabled != profile_data.get('two_factor_enabled'):
                    profile.two_factor_enabled = profile_data.get('two_factor_enabled')
                    modified_fields.append('two_factor_enabled')
                    
                # Sauvegarder le profil uniquement si des champs ont été modifiés
                if modified_fields:
                    print(f"Sauvegarde du profil avec les champs modifiés: {modified_fields}")
                    profile.save(update_fields=modified_fields)
                
            # Sauvegarder les modifications de l'utilisateur
            serializer.save()
            
            return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['PATCH'])
    def photo(self, request):
        """
        PATCH /auth/users/photo/
        FormData avec 'profile_pic'
        """
        print("PATCH /auth/users/photo/ - Files:", request.FILES)
    
        user = request.user
    
        # Vérifier si le profil existe, sinon le créer
        try:
            profile = user.profile
            print("Profil trouvé pour l'utilisateur:", profile)
        except Exception as e:
            print(f"Erreur lors de l'accès au profil: {str(e)}")
            # Si le profil n'existe pas, on le crée
            from .models import UserProfile
            profile = UserProfile.objects.create(user=user)
            print("Profil créé pour l'utilisateur")
    
        if 'profile_pic' not in request.FILES:
            return Response({"error": "Aucun fichier reçu"}, status=400)
    
        # Si une photo existe déjà, on la supprime du système de fichiers
        if profile.profile_pic:
            try:
                old_file_path = profile.profile_pic.path
                if os.path.isfile(old_file_path):
                    os.remove(old_file_path)
                    print(f"Ancienne photo supprimée: {old_file_path}")
            except Exception as e:
                print(f"Erreur lors de la suppression de l'ancienne photo: {str(e)}")
    
        # Sauvegarde de la nouvelle photo
        profile.profile_pic = request.FILES['profile_pic']
        profile._request = request  # Attacher la requête pour les signaux
        profile.save(update_fields=['profile_pic'])  # Spécifier le champ à mettre à jour
    
        # S'assurer que l'URL est correctement formée
        if profile.profile_pic and hasattr(profile.profile_pic, 'url'):
            profile_pic_url = profile.profile_pic.url
            print(f"URL de la photo enregistrée: {profile_pic_url}")
        
            # Vérifier si le fichier existe sur le disque
            try:
                file_path = profile.profile_pic.path
                if os.path.isfile(file_path):
                    print(f"Le fichier existe sur le disque: {file_path}")
                else:
                    print(f"ATTENTION: Le fichier n'existe pas sur le disque: {file_path}")
            except Exception as e:
                print(f"Erreur lors de la vérification du fichier: {str(e)}")
        else:
            profile_pic_url = None
            print("URL de photo nulle ou non disponible")
    
        # Vérifier les permissions du répertoire media
        try:
            media_root = settings.MEDIA_ROOT
            if os.path.exists(media_root):
                print(f"Le répertoire media existe: {media_root}")
                # Vérifier les permissions
                permissions = oct(os.stat(media_root).st_mode & 0o777)
                print(f"Permissions du répertoire media: {permissions}")
            else:
                print(f"ATTENTION: Le répertoire media n'existe pas: {media_root}")
        except Exception as e:
            print(f"Erreur lors de la vérification du répertoire media: {str(e)}")
    
        return Response({"profile_pic": profile_pic_url}, status=200)

    @action(detail=False, methods=['POST'])
    def change_password(self, request):
        """
        POST /auth/users/change-password/
        {
            "current_password": "...",
            "new_password": "..."
        }
        """
        serializer = ChangePasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user = request.user
        current_password = serializer.validated_data['current_password']
        new_password = serializer.validated_data['new_password']
        
        # Vérifier le mot de passe actuel
        if not user.check_password(current_password):
            return Response({"error": "Mot de passe actuel incorrect"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Mettre à jour le mot de passe
        user.set_password(new_password)
        user.save()
        
        # On force la déconnexion des autres sessions en générant un nouveau token
        refresh = RefreshToken.for_user(user)
        
        # Créer une notification de changement de mot de passe
        try:
            from notifications.signals import notify_password_changed
            notify_password_changed(user, request)
        except ImportError:
            # Si le module de notifications n'est pas disponible, on continue sans erreur
            pass
        
        return Response({
            "detail": "Mot de passe modifié avec succès",
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['GET', 'POST', 'DELETE'])
    def sessions(self, request):
        """
        GET /auth/users/sessions/ => Liste des sessions
        POST /auth/users/sessions/ => Mise à jour d'une session
        DELETE /auth/users/sessions/ => Suppression de sessions
        """
        if request.method == 'GET':
            sessions = UserSession.objects.filter(user=request.user)
            serializer = UserSessionSerializer(sessions, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        elif request.method == 'DELETE':
            # Suppression de toutes les sessions sauf la session courante
            session_id = request.query_params.get('id')
            
            if session_id == 'all-except-current':
                UserSession.objects.filter(user=request.user, is_current=False).delete()
                return Response({"detail": "Toutes les autres sessions ont été déconnectées"}, status=status.HTTP_200_OK)
            
            elif session_id:
                try:
                    session = UserSession.objects.get(id=session_id, user=request.user)
                    session.delete()
                    return Response({"detail": "Session déconnectée"}, status=status.HTTP_200_OK)
                except UserSession.DoesNotExist:
                    return Response({"error": "Session non trouvée"}, status=status.HTTP_404_NOT_FOUND)
            
            return Response({"error": "Paramètre 'id' requis"}, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['POST', 'GET'])
    def two_factor(self, request):
        """
        POST /auth/users/two-factor/ => Activer/désactiver 2FA
        GET /auth/users/two-factor/ => Récupérer le QR code pour 2FA
        """
        if request.method == 'GET':
            # S'assurer que le profil existe
            try:
                profile = request.user.profile
            except UserProfile.DoesNotExist:
                profile = UserProfile.objects.create(user=request.user)
            
            # Si 2FA n'est pas activé, générer une nouvelle clé secrète
            if not profile.two_factor_secret:
                profile.generate_2fa_secret()
            
            # Générer le QR code
            qr_code = profile.get_2fa_qr_code()
            
            return Response({
                "secret": profile.two_factor_secret,
                "qr_code": qr_code,
                "is_enabled": profile.two_factor_enabled
            }, status=status.HTTP_200_OK)
        
        elif request.method == 'POST':
            serializer = TwoFactorSetupSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            enable = serializer.validated_data['enable']
            code = serializer.validated_data.get('code')
            
            # S'assurer que le profil existe
            try:
                profile = request.user.profile
            except UserProfile.DoesNotExist:
                profile = UserProfile.objects.create(user=request.user)
            
            if enable:
                # Activation de 2FA
                # Vérifier que la clé secrète existe, sinon la générer
                if not profile.two_factor_secret:
                    profile.generate_2fa_secret()
                
                # Vérifier le code
                if not code:
                    return Response({"error": "Code de vérification requis"}, status=status.HTTP_400_BAD_REQUEST)
                
                if not profile.verify_2fa_code(code):
                    return Response({"error": "Code de vérification invalide"}, status=status.HTTP_400_BAD_REQUEST)
                
                # Attacher la requête pour les signaux
                profile._request = request
                
                # Activer 2FA
                profile.two_factor_enabled = True
                profile.save(update_fields=['two_factor_enabled'])
                
                return Response({
                    "detail": "Authentification à deux facteurs activée",
                    "is_enabled": True
                }, status=status.HTTP_200_OK)
            
            else:
                # Désactivation de 2FA
                # Attacher la requête pour les signaux
                profile._request = request
                
                profile.two_factor_enabled = False
                profile.save(update_fields=['two_factor_enabled'])
                
                return Response({
                    "detail": "Authentification à deux facteurs désactivée",
                    "is_enabled": False
                }, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['POST'])
    def delete_account(self, request):
        """
        POST /auth/users/delete_account/ => Envoyer demande de suppression seulement
        """
        serializer = DeleteAccountSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        password = serializer.validated_data['password']
        
        # Vérifier le mot de passe
        if not request.user.check_password(password):
            return Response({"error": "Mot de passe incorrect"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Créer ou récupérer le token de suppression
        token, created = DeleteAccountToken.objects.get_or_create(user=request.user)
        if not created and not token.is_valid:
            token.delete()
            token = DeleteAccountToken.objects.create(user=request.user)
        
        return Response({
            "detail": "Une demande de suppression de compte a été initiée.",
            "token": token.token
        }, status=status.HTTP_200_OK)
    
    # NOUVEAU: Action pour récupérer le statut E2E
    @action(detail=False, methods=['GET'])
    def e2e_status(self, request):
        """
        Récupère le statut E2E de l'utilisateur
        GET /auth/users/e2e_status/
        """
        try:
            profile = request.user.profile
            return Response({
                'e2e_status': profile.e2e_status
            })
        except UserProfile.DoesNotExist:
            # Créer le profil s'il n'existe pas
            profile = UserProfile.objects.create(user=request.user)
            return Response({
                'e2e_status': profile.e2e_status
            })
            

class TwoFactorAuthView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = TwoFactorAuthSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        code = serializer.validated_data['code']
        remember = serializer.validated_data.get('remember', 'false')
        
        print(f"DEBUG 2FA ENDPOINT: username={username}, code={code}, remember={remember}")
        
        try:
            user = User.objects.get(username=username)
            
            # Vérifier le mot de passe
            if not user.check_password(password):
                return Response({"error": "Mot de passe incorrect"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Vérifier si l'utilisateur a la 2FA activée
            if not hasattr(user, 'profile') or not user.profile.two_factor_enabled:
                return Response({"error": "2FA non activée pour cet utilisateur"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Vérifier le code
            if not user.profile.verify_2fa_code(code):
                return Response({"error": "Code 2FA invalide"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Créer les tokens
            refresh = RefreshToken.for_user(user)
            
            # Ajuster la durée de vie si remember=true
            if remember == 'true':
                refresh.set_exp(lifetime=timedelta(days=7))
            
            # Enregistrer la session utilisateur (si nécessaire)
            ip_address = self._get_client_ip(request)
            user_agent_string = request.META.get('HTTP_USER_AGENT', '')
            
            # Parser le User-Agent
            user_agent = parse(user_agent_string)
            browser = f"{user_agent.browser.family} {user_agent.browser.version_string}"
            device = f"{user_agent.device.brand} {user_agent.device.model}" if user_agent.device.brand else user_agent.os.family
            
            # Essayer de déterminer la location basée sur l'IP
            location = self._get_location_from_ip(ip_address)
            
            # Désactiver l'attribut is_current pour toutes les sessions existantes de l'utilisateur
            UserSession.objects.filter(user=user, is_current=True).update(is_current=False)
            
            # Créer une nouvelle session
            UserSession.objects.create(
                user=user,
                ip_address=ip_address,
                user_agent=user_agent_string,
                location=location,
                device=device,
                browser=browser,
                is_current=True
            )
            
            return Response({
                "access": str(refresh.access_token),
                "refresh": str(refresh)
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response({"error": "Utilisateur non trouvé"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(f"ERROR 2FA ENDPOINT: {str(e)}")
            return Response({"error": f"Erreur serveur: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _get_client_ip(self, request):
        """Récupère l'adresse IP du client"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _get_location_from_ip(self, ip):
        """Essaie de déterminer la localisation à partir de l'adresse IP"""
        try:
            # Utilisation d'un service gratuit de géolocalisation IP
            response = requests.get(f'https://ipapi.co/{ip}/json/')
            if response.status_code == 200:
                data = response.json()
                city = data.get('city', '')
                country = data.get('country_name', '')
                if city and country:
                    return f"{city}, {country}"
                elif country:
                    return country
        except Exception:
            pass
        return "Localisation inconnue"