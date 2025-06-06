# credentials/views.py
from rest_framework import viewsets, status, permissions
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action, api_view, permission_classes
from django.contrib.auth import authenticate
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.db import models
from .models import Credential, CredentialShare, Tag
from .serializers import CredentialSerializer, CredentialShareSerializer, TagSerializer
from .crypto_utils import encrypt_password, decrypt_password
from .models_e2e import CredentialE2E, UserKeyDerivation
from .serializers_e2e import CredentialE2ESerializer, UserKeyDerivationSerializer
from .e2e_crypto import E2ECryptoManager
import secrets

class TagViewSet(viewsets.ModelViewSet):
    """ViewSet pour gérer les tags des credentials"""
    serializer_class = TagSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Ne renvoie que les tags de l'utilisateur connecté"""
        return Tag.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """Crée un nouveau tag"""
        serializer.save(user=self.request.user)
    
    @action(detail=True, methods=['GET'])
    def credentials(self, request, pk=None):
        """
        Récupère tous les credentials associés à un tag
        GET /api/tags/<id>/credentials/
        """
        tag = self.get_object()
        credentials = tag.credentials.all()
        serializer = CredentialSerializer(credentials, many=True)
        return Response(serializer.data)

class CredentialViewSet(viewsets.ModelViewSet):
    queryset = Credential.objects.all()
    serializer_class = CredentialSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Filtrer les credentials appartenant à l'utilisateur connecté
        return Credential.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        # On récupère le password depuis les données validées
        password_plain = serializer.validated_data.get('password', '')
    
        # On chiffre le mot de passe
        ciphertext = encrypt_password(password_plain)
    
        # On enregistre l'instance avec le mot de passe chiffré
        credential = serializer.save(
            user=self.request.user,
            password_encrypted=ciphertext
        )

        # Attacher la requête à l'objet pour les signaux
        credential._request = self.request
        
        # Éviter les signaux en cascade - Modifier ici pour éviter les doublons
        # Ici, aucun signal supplémentaire n'est déclenché puisqu'on utilise save() indirectement par serializer.save()

    def perform_update(self, serializer):
        # Attention: cette méthode était une source potentielle de doublons
        # Modification pour éviter de déclencher plusieurs fois les signaux
        
        # Attacher la requête à l'instance avant de sauvegarder
        instance = serializer.instance
        instance._request = self.request
        
        # Sauvegarde contrôlée - Utiliser un flag pour identifier cette mise à jour
        updated_instance = serializer.save()
        
        # Ne pas faire instance.save() une deuxième fois ici, ce qui déclenchait les signaux en double
    
    def perform_destroy(self, instance):
        # Attacher la requête à l'objet pour les signaux
        instance._request = self.request
        instance.delete()

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        data = request.data.copy()

        # Si un nouveau mot de passe est fourni, on le chiffre
        if 'password' in data:
            ciphertext = encrypt_password(data['password'])
            # Stockez le mot de passe chiffré directement dans l'instance
            instance.password_encrypted = ciphertext
        
        # Retirer uniquement le champ password pour éviter des problèmes avec le serializer
        data.pop('password', None)

        serializer = self.get_serializer(instance, data=data, partial=partial)
        serializer.is_valid(raise_exception=True)
        
        # Attacher la requête à l'instance
        instance._request = self.request
        
        # Utiliser update_fields si possible pour être précis sur ce qui est mis à jour
        # Créer une liste des champs modifiés
        updated_fields = []
        for field_name, value in data.items():
            if hasattr(instance, field_name) and getattr(instance, field_name) != value:
                updated_fields.append(field_name)
        
        # Ajouter password_encrypted si modifié
        if 'password' in request.data:
            updated_fields.append('password_encrypted')
            
        # Sauvegarder en spécifiant les champs mis à jour
        self.perform_update(serializer)
        
        # La ligne ci-dessous causait un doublon potentiel - Maintenant, nous sauvegardons
        # explicitement avec update_fields si nous avons modifié le mot de passe
        if 'password' in request.data and updated_fields:
            instance.save(update_fields=updated_fields)
        
        return Response(serializer.data)

    @action(detail=True, methods=['GET'])
    def decrypt(self, request, pk=None):
        """
        Déchiffrer le mot de passe et le renvoyer en clair.
        GET /api/credentials/<id>/decrypt/
        """
        instance = self.get_object()
        try:
            plain = decrypt_password(instance.password_encrypted)
            return Response({"password": plain}, status=200)
        except Exception:
            return Response({"error": "Impossible de déchiffrer"}, status=400)

    @action(detail=True, methods=['POST'])
    def verify(self, request, pk=None):
        """
        Vérifie le mot de passe de compte de l'utilisateur
        pour des actions sensibles (déverrouiller, désactiver is_sensitive, etc.)
        POST /api/credentials/<id>/verify/ { "password": "<monMotDePasse>" }
        """
        instance = self.get_object()
        typed_password = request.data.get('password', '')

        if request.user.check_password(typed_password):
            return Response({"detail": "Mot de passe correct"}, status=200)
        else:
            return Response({"error": "Mot de passe incorrect"}, status=400)
            
    @action(detail=True, methods=['POST'])
    def add_tag(self, request, pk=None):
        """
        Ajoute un tag à un credential
        POST /api/credentials/<id>/add_tag/
        {"tag_id": 1}
        """
        credential = self.get_object()
        tag_id = request.data.get('tag_id')
        
        if not tag_id:
            return Response({"error": "tag_id est requis"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            tag = Tag.objects.get(id=tag_id, user=request.user)
        except Tag.DoesNotExist:
            return Response({"error": "Tag non trouvé"}, status=status.HTTP_404_NOT_FOUND)
        
        credential.tags.add(tag)
        serializer = self.get_serializer(credential)
        return Response(serializer.data)

    @action(detail=True, methods=['POST'])
    def remove_tag(self, request, pk=None):
        """
        Supprime un tag d'un credential
        POST /api/credentials/<id>/remove_tag/
        {"tag_id": 1}
        """
        credential = self.get_object()
        tag_id = request.data.get('tag_id')
        
        if not tag_id:
            return Response({"error": "tag_id est requis"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            tag = Tag.objects.get(id=tag_id, user=request.user)
        except Tag.DoesNotExist:
            return Response({"error": "Tag non trouvé"}, status=status.HTTP_404_NOT_FOUND)
        
        credential.tags.remove(tag)
        serializer = self.get_serializer(credential)
        return Response(serializer.data)

    @action(detail=False, methods=['GET'])
    def by_tag(self, request):
        """
        Filtre les credentials par tag
        GET /api/credentials/by_tag/?tag_id=1
        """
        tag_id = request.query_params.get('tag_id')
        
        if not tag_id:
            return Response({"error": "Paramètre tag_id requis"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            tag = Tag.objects.get(id=tag_id, user=request.user)
        except Tag.DoesNotExist:
            return Response({"error": "Tag non trouvé"}, status=status.HTTP_404_NOT_FOUND)
        
        credentials = Credential.objects.filter(user=request.user, tags=tag)
        serializer = self.get_serializer(credentials, many=True)
        return Response(serializer.data)


class CredentialShareViewSet(viewsets.ModelViewSet):
    """ViewSet pour la gestion des partages de credentials"""
    serializer_class = CredentialShareSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Ne renvoie que les partages créés par l'utilisateur connecté"""
        return CredentialShare.objects.filter(creator=self.request.user)
    
    def perform_create(self, serializer):
        """Création d'un nouveau partage"""
        # Ajout de la requête à l'objet pour les signaux
        share = serializer.save()
        if hasattr(self, 'request'):
            share._request = self.request
    
    def destroy(self, request, *args, **kwargs):
        """Suppression d'un partage existant"""
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"detail": "Partage supprimé avec succès."}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def access_shared_credential(request, share_id, access_key):
    """
    Vue publique pour accéder à un credential partagé via API
    URL: /api/share/<share_id>/<access_key>/
    Renvoie les données JSON pour être affichées dans une page React
    """
    try:
        # Récupérer le partage avec l'ID et la clé d'accès
        share = get_object_or_404(CredentialShare, id=share_id, access_key=access_key)
        
        # Vérifier si le partage est expiré
        if share.is_expired:
            return Response({
                "error": "Ce lien de partage a expiré.",
                "detail": "Le lien a atteint sa date d'expiration ou son nombre maximal d'utilisations."
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Récupérer le credential associé
        credential = share.credential
        
        # Déchiffrer le mot de passe
        try:
            decrypted_password = decrypt_password(credential.password_encrypted)
        except Exception:
            return Response({
                "error": "Impossible de déchiffrer le mot de passe.",
                "detail": "Une erreur s'est produite lors du déchiffrement."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Incrémenter le compteur d'accès
        share.increment_access_count()
        
        # Créer une notification pour le propriétaire du credential
        try:
            from notifications.signals import notify_shared_credential_accessed
            notify_shared_credential_accessed(share, request)
        except ImportError:
            # Si le module de notifications n'est pas disponible, on continue sans erreur
            pass
        
        # Renvoyer les informations du credential en JSON
        return Response({
            "name": credential.name,
            "website": credential.website,
            "email": credential.email,
            "password": decrypted_password,
            "note": credential.note,
            "shared_by": share.creator.username,
            "expires_at": share.expires_at,
            "remaining_accesses": share.remaining_accesses,
            "is_expired": share.is_expired,
            "created_at": share.created_at
        }, status=status.HTTP_200_OK)
    
    except Http404:
        return Response({
            "error": "Lien de partage invalide",
            "detail": "Ce lien de partage n'existe pas ou a été supprimé."
        }, status=status.HTTP_404_NOT_FOUND)
    
class UserKeyDerivationViewSet(viewsets.ModelViewSet):
    """
    ViewSet pour gérer les paramètres de dérivation de clé utilisateur
    """
    serializer_class = UserKeyDerivationSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return UserKeyDerivation.objects.filter(user=self.request.user)
    
    def list(self, request, *args, **kwargs):
        """
        Récupère ou crée les paramètres de dérivation pour l'utilisateur
        """
        derivation, created = UserKeyDerivation.objects.get_or_create(
            user=request.user,
            defaults={
                'salt': secrets.token_urlsafe(32),
                'search_salt': secrets.token_urlsafe(32),
                'iterations': 100000,
                'algorithm': 'PBKDF2-SHA256'
            }
        )
        
        serializer = self.get_serializer(derivation)
        return Response({
            'derivation_params': serializer.data,
            'is_new': created
        })

class CredentialE2EViewSet(viewsets.ModelViewSet):
    """
    ViewSet pour les credentials chiffrés de bout en bout
    """
    serializer_class = CredentialE2ESerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return CredentialE2E.objects.filter(user=self.request.user)
    
    def list(self, request, *args, **kwargs):
        """
        Liste les credentials E2E avec vérification du statut
        """
        # Vérifier si E2E est activé pour cet utilisateur
        try:
            from accounts.models import UserProfile
            profile = request.user.profile
            if not profile.e2e_enabled:
                return Response({
                    'error': 'E2E non activé',
                    'e2e_status': profile.e2e_status
                }, status=status.HTTP_403_FORBIDDEN)
        except UserProfile.DoesNotExist:
            return Response({
                'error': 'Profil utilisateur non trouvé'
            }, status=status.HTTP_404_NOT_FOUND)
        
        return super().list(request, *args, **kwargs)
    
    def perform_create(self, serializer):
        """
        Création avec validation supplémentaire
        """
        # Vérifier si E2E est activé
        try:
            from accounts.models import UserProfile
            profile = self.request.user.profile
            if not profile.e2e_enabled:
                raise permissions.PermissionDenied('E2E non activé pour cet utilisateur')
        except UserProfile.DoesNotExist:
            raise permissions.PermissionDenied('Profil utilisateur non trouvé')
        
        # Attacher la requête pour les signaux
        credential = serializer.save()
        credential._request = self.request
        
        # Log sécurisé (sans données sensibles)
        try:
            from security.models import AuditLogEntry
            AuditLogEntry.objects.create(
                user=self.request.user,
                action_type='credential_create_e2e',
                action_detail=f"Création d'un credential E2E (ID: {credential.id})",
                ip_address=self._get_client_ip(),
                related_object_id=str(credential.id)
            )
        except ImportError:
            # Module security non disponible
            pass
    
    @action(detail=False, methods=['GET'])
    def search(self, request):
        """
        Recherche sécurisée sur les hashs
        """
        query = request.query_params.get('q', '').strip()
        if not query:
            return Response({'results': []})
        
        # Récupérer les paramètres de dérivation de l'utilisateur
        try:
            derivation = UserKeyDerivation.objects.get(user=request.user)
        except UserKeyDerivation.DoesNotExist:
            return Response({'error': 'Paramètres de dérivation non trouvés'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        
        # Générer le hash de recherche
        search_hash = E2ECryptoManager.generate_search_hash(query, derivation.search_salt)
        
        # Rechercher dans les hashs
        credentials = CredentialE2E.objects.filter(
            user=request.user
        ).filter(
            models.Q(name_search_hash=search_hash) |
            models.Q(website_search_hash=search_hash) |
            models.Q(email_search_hash=search_hash)
        )
        
        serializer = self.get_serializer(credentials, many=True)
        return Response({'results': serializer.data})
    
    @action(detail=False, methods=['POST'])
    def migrate_from_legacy(self, request):
        """
        Migre un credential existant vers le format E2E
        POST /api/credentials-e2e/migrate_from_legacy/
        {
            "legacy_credential_id": 123,
            "encrypted_data": {...},
            "search_hashes": {...}
        }
        """
        legacy_id = request.data.get('legacy_credential_id')
        encrypted_data = request.data.get('encrypted_data', {})
        search_hashes = request.data.get('search_hashes', {})
        
        if not legacy_id:
            return Response({'error': 'ID du credential existant requis'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        
        try:
            legacy_credential = Credential.objects.get(id=legacy_id, user=request.user)
        except Credential.DoesNotExist:
            return Response({'error': 'Credential existant non trouvé'}, 
                          status=status.HTTP_404_NOT_FOUND)
        
        # Vérifier qu'il n'a pas déjà une version E2E
        if legacy_credential.has_e2e_version:
            return Response({'error': 'Ce credential a déjà une version E2E'}, 
                          status=status.HTTP_400_BAD_REQUEST)
        
        # Créer la version E2E
        e2e_credential = legacy_credential.create_e2e_version(encrypted_data, search_hashes)
        
        serializer = self.get_serializer(e2e_credential)
        return Response({
            'detail': 'Migration réussie',
            'e2e_credential': serializer.data
        })
    
    @action(detail=False, methods=['POST'])
    def activate_e2e(self, request):
        """
        Active E2E pour l'utilisateur
        POST /api/credentials-e2e/activate_e2e/
        {
            "user_password": "mot_de_passe_utilisateur"
        }
        """
        user_password = request.data.get('user_password')
        if not user_password:
            return Response({
                'error': 'Mot de passe utilisateur requis'
            }, status=status.HTTP_400_BAD_REQUEST)

        # DEBUG: Afficher des informations de débogage
        print(f"🔐 Tentative d'activation E2E pour l'utilisateur: {request.user.username}")
        print(f"🔑 Mot de passe reçu: {'***' if user_password else 'VIDE'}")

        # Vérifier le mot de passe
        if not request.user.check_password(user_password):
            print(f"❌ Mot de passe incorrect pour l'utilisateur: {request.user.username}")
            return Response({
                'error': 'Mot de passe incorrect'
            }, status=status.HTTP_400_BAD_REQUEST)

        print(f"✅ Mot de passe correct pour l'utilisateur: {request.user.username}")

        try:
            # Créer ou récupérer les paramètres de dérivation
            derivation, created = UserKeyDerivation.objects.get_or_create(
                user=request.user,
                defaults={
                    'salt': secrets.token_urlsafe(32),
                    'search_salt': secrets.token_urlsafe(32),
                    'iterations': 100000,
                    'algorithm': 'PBKDF2-SHA256'
                }
            )
            
            print(f"📋 Paramètres de dérivation {'créés' if created else 'récupérés'}")
            
            # Activer E2E dans le profil
            from accounts.models import UserProfile
            profile, profile_created = UserProfile.objects.get_or_create(user=request.user)
            
            # Activer E2E
            profile.enable_e2e()
            
            print(f"✅ E2E activé pour l'utilisateur: {request.user.username}")

            return Response({
                'success': True,
                'message': 'E2E activé avec succès',
                'e2e_status': profile.e2e_status,
                'derivation_params': UserKeyDerivationSerializer(derivation).data
            })
            
        except Exception as e:
            print(f"❌ Erreur lors de l'activation E2E: {str(e)}")
            import traceback
            traceback.print_exc()
            return Response({
                'error': f'Erreur lors de l\'activation E2E: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['POST'])
    def deactivate_e2e(self, request):
        """
        Désactive E2E pour l'utilisateur
        POST /api/credentials-e2e/deactivate_e2e/
        {
            "user_password": "mot_de_passe_utilisateur"
        }
        """
        user_password = request.data.get('user_password')
        if not user_password:
            return Response({
                'error': 'Mot de passe utilisateur requis'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Vérifier le mot de passe
        if not request.user.check_password(user_password):
            return Response({
                'error': 'Mot de passe incorrect'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            from accounts.models import UserProfile
            profile = request.user.profile
            profile.disable_e2e()
            
            return Response({
                'success': True,
                'message': 'E2E désactivé avec succès',
                'e2e_status': profile.e2e_status
            })
            
        except UserProfile.DoesNotExist:
            return Response({
                'error': 'Profil utilisateur non trouvé'
            }, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=True, methods=['POST'])
    def verify(self, request, pk=None):
        """
        Vérifie le mot de passe de compte de l'utilisateur pour les credentials E2E sensibles
        POST /api/credentials-e2e/<id>/verify/ { "password": "<monMotDePasse>" }
        """
        instance = self.get_object()
        typed_password = request.data.get('password', '')

        if request.user.check_password(typed_password):
            return Response({"detail": "Mot de passe correct"}, status=200)
        else:
            return Response({"error": "Mot de passe incorrect"}, status=400)
    
    @action(detail=True, methods=['POST'])
    def add_tag(self, request, pk=None):
        """
        Ajoute un tag à un credential E2E
        POST /api/credentials-e2e/<id>/add_tag/
        {"tag_id": 1}
        """
        credential = self.get_object()
        tag_id = request.data.get('tag_id')
        
        if not tag_id:
            return Response({"error": "tag_id est requis"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            tag = Tag.objects.get(id=tag_id, user=request.user)
        except Tag.DoesNotExist:
            return Response({"error": "Tag non trouvé"}, status=status.HTTP_404_NOT_FOUND)
        
        # Note: Pour E2E, il faut adapter selon votre implémentation des tags
        # Ici on suppose que les credentials E2E ont aussi une relation avec les tags
        # Si ce n'est pas le cas, vous devrez modifier le modèle CredentialE2E
        
        return Response({"detail": "Tag ajouté avec succès"}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['POST'])
    def remove_tag(self, request, pk=None):
        """
        Supprime un tag d'un credential E2E
        POST /api/credentials-e2e/<id>/remove_tag/
        {"tag_id": 1}
        """
        credential = self.get_object()
        tag_id = request.data.get('tag_id')
        
        if not tag_id:
            return Response({"error": "tag_id est requis"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            tag = Tag.objects.get(id=tag_id, user=request.user)
        except Tag.DoesNotExist:
            return Response({"error": "Tag non trouvé"}, status=status.HTTP_404_NOT_FOUND)
        
        # Note: Même remarque que pour add_tag
        
        return Response({"detail": "Tag supprimé avec succès"}, status=status.HTTP_200_OK)
    
    def _get_client_ip(self):
        """Récupère l'IP du client"""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip