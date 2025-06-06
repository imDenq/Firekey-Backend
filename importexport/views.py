# importexport/views.py
import os
import uuid
import tempfile
import json
import logging
from datetime import datetime
from typing import Dict, Any

from django.http import HttpResponse, JsonResponse, FileResponse
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.utils import timezone

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework import status, viewsets

from .models import ImportHistory, ExportHistory, ImportFileStatus
from .serializers import (
    ImportHistorySerializer, 
    ExportHistorySerializer, 
    ImportFileStatusSerializer,
    ImportPreviewCredentialSerializer,
    ImportRequestSerializer,
    ExportRequestSerializer
)
from .import_handlers import get_import_handler
from .export_handlers import get_export_handler
from .temp_file_manager import temp_file_manager

logger = logging.getLogger(__name__)

class ImportHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet pour consulter l'historique des imports"""
    serializer_class = ImportHistorySerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Ne renvoie que l'historique de l'utilisateur connecté"""
        return ImportHistory.objects.filter(user=self.request.user)

class ExportHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet pour consulter l'historique des exports"""
    serializer_class = ExportHistorySerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Ne renvoie que l'historique de l'utilisateur connecté"""
        return ExportHistory.objects.filter(user=self.request.user)

class FileUploadView(APIView):
    """Vue pour télécharger un fichier d'import et l'analyser"""
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Gère le téléchargement et l'analyse préliminaire d'un fichier d'import.
        
        Paramètres (form-data):
        - file: Le fichier à importer
        - source: La source du fichier (ex: 'google', 'bitwarden', 'csv')  
        - password (optionnel): Mot de passe pour déchiffrer le fichier si nécessaire
        """
        try:
            # Vérifier si le fichier est présent
            if 'file' not in request.FILES:
                return Response(
                    {"error": "Aucun fichier n'a été fourni"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            file = request.FILES['file']
            source = request.data.get('source', 'csv')
            password = request.data.get('password', '')
            
            # Vérifier la taille du fichier (limite à 10MB)
            if file.size > 10 * 1024 * 1024:  # 10MB
                return Response(
                    {"error": "Le fichier est trop volumineux (limite: 10MB)"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Générer un identifiant unique pour ce fichier
            file_id = str(uuid.uuid4())
            
            # Lire le contenu du fichier
            file_content = file.read()
            
            # Métadonnées du fichier
            metadata = {
                'source': source,
                'filename': file.name,
                'size': len(file_content),
                'content_type': file.content_type,
                'uploaded_by': request.user.username,
                'uploaded_at': timezone.now().isoformat()
            }
            
            # Stocker le fichier de manière chiffrée
            try:
                encrypted_path = temp_file_manager.store_encrypted_file(
                    file_id, file_content, metadata
                )
            except Exception as e:
                logger.error(f"Erreur lors du stockage chiffré: {str(e)}")
                return Response(
                    {"error": "Erreur lors du stockage sécurisé du fichier"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Créer un enregistrement pour suivre l'analyse
            file_status = ImportFileStatus.objects.create(
                user=request.user,
                file_id=file_id,
                source=source,
                file_name=file.name,
                analysis_status='analyzing'
            )
            
            # Analyser le fichier pour prévisualisation
            try:
                # Obtenir le handler approprié pour la source
                handler = get_import_handler(source, request.user, file_content, password)
                
                # Analyser le fichier pour prévisualisation
                analysis_result = handler.analyze()
                
                # Mettre à jour le statut avec les résultats
                file_status.total_credentials = analysis_result.get('stats', {}).get('total', 0)
                file_status.new_credentials = analysis_result.get('stats', {}).get('new', 0)
                file_status.duplicate_credentials = analysis_result.get('stats', {}).get('duplicate', 0)
                file_status.conflict_credentials = analysis_result.get('stats', {}).get('conflict', 0)
                file_status.analysis_status = 'ready'
                file_status.save()
                
                # Renvoyer un récapitulatif de l'analyse
                serializer = ImportFileStatusSerializer(file_status)
                
                return Response({
                    "file_status": serializer.data,
                    "preview": analysis_result.get('credentials', [])[:5]  # Échantillon des 5 premiers
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                # En cas d'erreur, supprimer le fichier chiffré et mettre à jour le statut
                temp_file_manager.delete_file(file_id)
                
                file_status.analysis_status = 'error'
                file_status.error_message = str(e)
                file_status.save()
                
                logger.error(f"Erreur lors de l'analyse du fichier: {str(e)}")
                return Response(
                    {"error": f"Erreur lors de l'analyse du fichier: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        except Exception as e:
            logger.error(f"Erreur lors du téléchargement du fichier: {str(e)}")
            return Response(
                {"error": f"Erreur lors du téléchargement: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ImportPreviewView(APIView):
    """Vue pour obtenir la prévisualisation complète d'un fichier d'import"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request, file_id):
        """
        Renvoie la prévisualisation complète des credentials à importer.
        
        URL: /api/import-export/preview/{file_id}/
        """
        try:
            # Vérifier si le fichier existe et appartient à l'utilisateur
            try:
                file_status = ImportFileStatus.objects.get(
                    file_id=file_id,
                    user=request.user,
                    analysis_status='ready'
                )
            except ImportFileStatus.DoesNotExist:
                return Response(
                    {"error": "Fichier non trouvé ou analyse non terminée"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Vérifier si le fichier n'est pas expiré
            if file_status.is_expired:
                # Supprimer le fichier chiffré expiré
                temp_file_manager.delete_file(file_id)
                file_status.delete()
                
                return Response(
                    {"error": "Ce fichier a expiré. Veuillez le télécharger à nouveau."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Charger le fichier chiffré
            try:
                file_content, metadata = temp_file_manager.load_encrypted_file(file_id)
            except FileNotFoundError:
                # Le fichier n'existe plus, supprimer l'enregistrement
                file_status.delete()
                return Response(
                    {"error": "Le fichier n'existe plus. Veuillez le télécharger à nouveau."},
                    status=status.HTTP_404_NOT_FOUND
                )
            except Exception as e:
                logger.error(f"Erreur lors du chargement du fichier chiffré: {str(e)}")
                return Response(
                    {"error": "Erreur lors du chargement du fichier"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Récupérer le mot de passe si nécessaire
            password = request.query_params.get('password', '')
            
            # Obtenir le handler approprié pour la source
            handler = get_import_handler(file_status.source, request.user, file_content, password)
            
            # Analyser le fichier pour prévisualisation
            analysis_result = handler.analyze()
            
            # Convertir les credentials en format lisible par l'API
            credentials = analysis_result.get('credentials', [])
            serializer = ImportPreviewCredentialSerializer(credentials, many=True)
            
            return Response({
                "file_status": ImportFileStatusSerializer(file_status).data,
                "credentials": serializer.data,
                "stats": analysis_result.get('stats', {}),
                "metadata": metadata  # Inclure les métadonnées du fichier
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Erreur lors de la prévisualisation: {str(e)}")
            return Response(
                {"error": f"Erreur lors de la prévisualisation: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ImportExecuteView(APIView):
    """Vue pour exécuter l'import final des credentials"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Exécute l'import final des credentials dans la base de données.
        
        Paramètres (JSON):
        - file_id: L'ID du fichier téléchargé et analysé
        - source: Source du fichier
        - password (optionnel): Mot de passe pour déchiffrer le fichier si nécessaire
        - merge_strategy: Stratégie de fusion ('skip', 'rename', 'overwrite', 'smart_merge')
        """
        try:
            # Valider les données d'entrée
            serializer = ImportRequestSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(
                    serializer.errors,
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Récupérer les données validées
            data = serializer.validated_data
            file_id = data['file_id']
            source = data['source']
            password = data.get('password', '')
            merge_strategy = data.get('merge_strategy', 'smart_merge')
            
            # Vérifier si le fichier existe et appartient à l'utilisateur
            try:
                file_status = ImportFileStatus.objects.get(
                    file_id=file_id,
                    user=request.user,
                    analysis_status='ready'
                )
                
                # Vérifier si le fichier n'est pas expiré
                if file_status.is_expired:
                    temp_file_manager.delete_file(file_id)
                    file_status.delete()
                    
                    return Response(
                        {"error": "Ce fichier a expiré. Veuillez le télécharger à nouveau."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
            except ImportFileStatus.DoesNotExist:
                return Response(
                    {"error": "Fichier non trouvé ou analyse non terminée"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Charger le fichier chiffré
            try:
                file_content, metadata = temp_file_manager.load_encrypted_file(file_id)
            except FileNotFoundError:
                file_status.delete()
                return Response(
                    {"error": "Le fichier n'existe plus. Veuillez le télécharger à nouveau."},
                    status=status.HTTP_404_NOT_FOUND
                )
            except Exception as e:
                logger.error(f"Erreur lors du chargement pour import: {str(e)}")
                return Response(
                    {"error": "Erreur lors du chargement du fichier"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Obtenir le handler approprié pour la source
            handler = get_import_handler(source, request.user, file_content, password)
            
            # Exécuter l'import
            import_result = handler.import_credentials(merge_strategy=merge_strategy)
            
            # Créer un historique d'import
            import_history = ImportHistory.objects.create(
                user=request.user,
                source=source,
                file_name=file_status.file_name,
                credentials_imported=import_result.get('imported', 0),
                credentials_skipped=import_result.get('skipped', 0),
                credentials_merged=import_result.get('merged', 0),
                status=import_result.get('status', 'success'),
                error_message=import_result.get('error', None)
            )
            
            # IMPORTANT: Supprimer le fichier chiffré et l'enregistrement de statut
            temp_file_manager.delete_file(file_id)
            file_status.delete()
            
            logger.info(f"Import terminé pour l'utilisateur {request.user.username}: "
                       f"{import_result.get('imported', 0)} importés, "
                       f"{import_result.get('skipped', 0)} ignorés, "
                       f"{import_result.get('merged', 0)} fusionnés")
            
            # Renvoyer les résultats
            return Response({
                "success": import_result.get('status') != 'error',
                "import_id": import_history.id,
                "results": {
                    "status": import_result.get('status', 'success'),
                    "imported": import_result.get('imported', 0),
                    "skipped": import_result.get('skipped', 0),
                    "merged": import_result.get('merged', 0),
                    "errors": import_result.get('errors', 0)
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de l'import: {str(e)}")
            return Response(
                {"error": f"Erreur lors de l'import: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ExportCredentialsView(APIView):
    """Vue pour exporter les credentials"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Exporte les credentials au format demandé.
        
        Paramètres (JSON):
        - format: Le format d'export ('firekey', 'csv', 'json', 'bitwarden')
        - encrypt: Booléen indiquant si l'export doit être chiffré (uniquement pour 'firekey')
        - password: Mot de passe pour le chiffrement (requis si encrypt=True)
        - include_tags: Booléen indiquant si les tags doivent être inclus
        - include_shared: Booléen indiquant si les credentials partagés doivent être inclus
        """
        try:
            # Valider les données d'entrée
            serializer = ExportRequestSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(
                    serializer.errors,
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Récupérer les données validées
            data = serializer.validated_data
            format = data['format']
            encrypt = data.get('encrypt', False)
            password = data.get('password', '')
            include_tags = data.get('include_tags', True)
            include_shared = data.get('include_shared', False)
            
            # Créer le handler d'export approprié
            handler = get_export_handler(
                format,
                request.user,
                encrypt=encrypt,
                password=password,
                include_tags=include_tags,
                include_shared=include_shared
            )
            
            # Générer l'export
            export_data = handler.generate_export()
            
            # Déterminer le type de contenu et le nom de fichier
            content_types = {
                'firekey': 'application/octet-stream',
                'csv': 'text/csv',
                'json': 'application/json',
                'bitwarden': 'text/csv'
            }
            
            extensions = {
                'firekey': 'fbak',
                'csv': 'csv',
                'json': 'json',
                'bitwarden': 'csv'
            }
            
            now = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"firekey_export_{now}.{extensions[format]}"
            
            # Créer un historique d'export
            ExportHistory.objects.create(
                user=request.user,
                format=format,
                encrypted=encrypt,
                credentials_exported=len(handler.get_credentials()),
                status='success'
            )
            
            logger.info(f"Export réussi pour {request.user.username}: "
                       f"format={format}, credentials={len(handler.get_credentials())}")
            
            # Renvoyer le fichier
            response = HttpResponse(
                export_data,
                content_type=content_types[format]
            )
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            
            return response
            
        except Exception as e:
            logger.error(f"Erreur lors de l'export: {str(e)}")
            
            # Créer un historique d'export avec erreur
            try:
                ExportHistory.objects.create(
                    user=request.user,
                    format=request.data.get('format', 'unknown'),
                    encrypted=request.data.get('encrypt', False),
                    credentials_exported=0,
                    status='error',
                    error_message=str(e)
                )
            except:
                pass  # Éviter les erreurs en cascade
            
            return Response(
                {"error": f"Erreur lors de l'export: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# Vue pour obtenir les options d'import/export disponibles
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_import_export_options(request):
    """
    Renvoie les options disponibles pour l'import/export.
    
    URL: /api/import-export/options/
    """
    return Response({
        "import_sources": [
            {"id": "google", "name": "Google Password Manager", "requires_password": False},
            {"id": "dashlane", "name": "Dashlane", "requires_password": True},
            {"id": "bitwarden", "name": "Bitwarden", "requires_password": True},
            {"id": "lastpass", "name": "LastPass", "requires_password": True},
            {"id": "onepassword", "name": "1Password", "requires_password": True},
            {"id": "keeper", "name": "Keeper", "requires_password": True},
            {"id": "csv", "name": "CSV (Generic)", "requires_password": False}
        ],
        "export_formats": [
            {"id": "firekey", "name": "FireKey (Recommandé)", "description": "Format natif chiffré pour FireKey"},
            {"id": "csv", "name": "CSV", "description": "Format compatible avec la plupart des gestionnaires de mots de passe"},
            {"id": "json", "name": "JSON", "description": "Format lisible par machine"},
            {"id": "bitwarden", "name": "Bitwarden CSV", "description": "Format CSV pour import vers Bitwarden"}
        ],
        "merge_strategies": [
            {"id": "smart_merge", "name": "Fusion intelligente", "description": "Combine les informations des deux sources"},
            {"id": "skip", "name": "Ignorer les doublons", "description": "N'importe que les nouveaux credentials"},
            {"id": "rename", "name": "Renommer", "description": "Crée des copies avec un nouveau nom"},
            {"id": "overwrite", "name": "Écraser", "description": "Remplace les credentials existants"}
        ]
    }, status=status.HTTP_200_OK)

# Vue pour le nettoyage manuel des fichiers expirés (optionnel, pour l'admin)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cleanup_temp_files(request):
    """
    Nettoie manuellement les fichiers temporaires expirés.
    Réservé aux administrateurs.
    """
    if not request.user.is_staff:
        return Response(
            {"error": "Accès non autorisé"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        max_age_hours = request.data.get('max_age_hours', 1)
        deleted_count = temp_file_manager.cleanup_expired_files(max_age_hours)
        
        return Response({
            "success": True,
            "deleted_files": deleted_count,
            "message": f"{deleted_count} fichiers temporaires supprimés"
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage: {str(e)}")
        return Response(
            {"error": f"Erreur lors du nettoyage: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )