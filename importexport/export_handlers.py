# importexport/export_handlers.py
import csv
import json
import io
import os
import hashlib
import hmac
import base64
import logging
from typing import Dict, List, Any
import tempfile
import zipfile
from datetime import datetime
from abc import ABC, abstractmethod
from django.contrib.auth.models import User
from django.conf import settings
from django.utils import timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from credentials.models import Credential, Tag
from credentials.crypto_utils import decrypt_password

logger = logging.getLogger(__name__)

class ExportHandler(ABC):
    """Classe abstraite pour tous les handlers d'export"""
    
    def __init__(self, user: User, include_tags: bool = True, include_shared: bool = False):
        self.user = user
        self.include_tags = include_tags
        self.include_shared = include_shared
        
    @abstractmethod
    def generate_export(self) -> bytes:
        """
        Génère le fichier d'export.
        Doit être implémentée par chaque handler.
        """
        pass
    
    def get_credentials(self) -> List[Dict[str, Any]]:
        """
        Récupère tous les credentials de l'utilisateur avec leurs informations.
        """
        credentials_list = []
        
        # Récupérer tous les credentials de l'utilisateur
        credentials = Credential.objects.filter(user=self.user)
        
        for cred in credentials:
            # Décrypter le mot de passe
            try:
                password = decrypt_password(cred.password_encrypted)
            except Exception as e:
                logger.error(f"Erreur lors du déchiffrement du mot de passe: {str(e)}")
                password = ""  # Mot de passe vide en cas d'erreur
            
            # Récupérer les tags si nécessaire
            tags = []
            if self.include_tags:
                tags = [tag.name for tag in cred.tags.all()]
            
            # Création d'un dictionnaire avec les données du credential
            credential_data = {
                'id': cred.id,
                'name': cred.name,
                'website': cred.website or '',
                'email': cred.email or '',
                'password': password,
                'note': cred.note or '',
                'is_sensitive': cred.is_sensitive,
                'created_at': cred.created_at.isoformat() if cred.created_at else '',
                'updated_at': cred.updated_at.isoformat() if cred.updated_at else '',
                'tags': tags
            }
            
            credentials_list.append(credential_data)
        
        # TODO: Ajouter la logique pour les credentials partagés si include_shared=True
        
        return credentials_list


class FireKeyExportHandler(ExportHandler):
    """Handler pour l'export au format FireKey natif (fichier chiffré)"""
    
    def __init__(self, user: User, include_tags: bool = True, include_shared: bool = False, 
                 encrypt: bool = True, password: str = None):
        super().__init__(user, include_tags, include_shared)
        self.encrypt = encrypt
        self.password = password
    
    def generate_export(self) -> bytes:
        """Génère un export au format FireKey (JSON chiffré)"""
        credentials = self.get_credentials()
        
        # Créer un dictionnaire avec toutes les données
        export_data = {
            'format': 'firekey',
            'version': '1.0',
            'timestamp': datetime.now().isoformat(),
            'user': self.user.username,
            'email': self.user.email,
            'credentials': credentials,
            'metadata': {
                'credentials_count': len(credentials),
                'include_tags': self.include_tags,
                'include_shared': self.include_shared,
                'exported_at': timezone.now().isoformat()
            }
        }
        
        # Conversion en JSON
        json_data = json.dumps(export_data, indent=2)
        
        # Si le chiffrement est activé, chiffrer les données
        if self.encrypt:
            if not self.password:
                raise ValueError("Un mot de passe est requis pour l'export chiffré")
            
            return self._encrypt_data(json_data.encode('utf-8'))
        
        return json_data.encode('utf-8')
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """
        Chiffre les données avec le mot de passe fourni
        Utilise AES-256-CBC avec un sel et un vecteur d'initialisation (IV)
        """
        try:
            # Dériver une clé à partir du mot de passe
            salt = os.urandom(16)
            iterations = 100000  # Nombre d'itérations pour PBKDF2
            
            # Dériver la clé
            key = hashlib.pbkdf2_hmac(
                'sha256',
                self.password.encode('utf-8'),
                salt,
                iterations,
                32  # 32 octets = 256 bits
            )
            
            # Générer un IV aléatoire
            iv = os.urandom(16)
            
            # Padding des données
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            # Chiffrer les données
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Calculer un HMAC pour vérifier l'intégrité
            mac = hmac.new(key, encrypted_data, hashlib.sha256).digest()
            
            # Construire l'en-tête FireKey
            header = {
                'format': 'firekey',
                'version': '1.0',
                'cipher': 'AES-256-CBC',
                'kdf': 'PBKDF2',
                'iterations': iterations,
                'salt': base64.b64encode(salt).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'mac': base64.b64encode(mac).decode('utf-8')
            }
            
            # Encoder l'en-tête en JSON
            header_json = json.dumps(header).encode('utf-8')
            
            # Construire le fichier final: 4 octets pour la taille de l'en-tête, l'en-tête, puis les données chiffrées
            header_size = len(header_json)
            result = header_size.to_bytes(4, byteorder='big')
            result += header_json
            result += encrypted_data
            
            return result
        
        except Exception as e:
            logger.error(f"Erreur lors du chiffrement des données: {str(e)}")
            raise ValueError(f"Impossible de chiffrer les données: {str(e)}")


class CSVExportHandler(ExportHandler):
    """Handler pour l'export au format CSV"""
    
    def generate_export(self) -> bytes:
        """Génère un export au format CSV"""
        credentials = self.get_credentials()
        
        # Créer un buffer en mémoire
        output = io.StringIO()
        
        # Définir les champs du CSV
        fieldnames = ['name', 'website', 'email', 'username', 'password', 'notes', 'is_sensitive']
        
        # Ajouter les tags si nécessaire
        if self.include_tags:
            fieldnames.append('tags')
        
        # Créer le writer CSV
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        # Écrire chaque credential
        for cred in credentials:
            row = {
                'name': cred['name'],
                'website': cred['website'],
                'email': cred['email'],
                'username': cred['email'],  # Utiliser email comme username par défaut
                'password': cred['password'],
                'notes': cred['note'],
                'is_sensitive': 'true' if cred['is_sensitive'] else 'false'
            }
            
            # Ajouter les tags séparés par des virgules
            if self.include_tags:
                row['tags'] = ', '.join(cred['tags'])
            
            writer.writerow(row)
        
        # Obtenir le contenu du buffer
        csv_data = output.getvalue()
        output.close()
        
        return csv_data.encode('utf-8')


class JSONExportHandler(ExportHandler):
    """Handler pour l'export au format JSON"""
    
    def generate_export(self) -> bytes:
        """Génère un export au format JSON"""
        credentials = self.get_credentials()
        
        # Créer un dictionnaire avec toutes les données
        export_data = {
            'format': 'json',
            'version': '1.0',
            'timestamp': datetime.now().isoformat(),
            'user': self.user.username,
            'email': self.user.email,
            'credentials': credentials,
            'metadata': {
                'credentials_count': len(credentials),
                'include_tags': self.include_tags,
                'include_shared': self.include_shared,
                'exported_at': timezone.now().isoformat()
            }
        }
        
        # Conversion en JSON
        json_data = json.dumps(export_data, indent=2)
        
        return json_data.encode('utf-8')


class BitwardenCSVExportHandler(ExportHandler):
    """Handler pour l'export au format CSV compatible avec Bitwarden"""
    
    def generate_export(self) -> bytes:
        """Génère un export au format CSV compatible avec Bitwarden"""
        credentials = self.get_credentials()
        
        # Créer un buffer en mémoire
        output = io.StringIO()
        
        # Définir les champs pour Bitwarden
        fieldnames = ['folder', 'favorite', 'type', 'name', 'notes', 'fields', 
                      'login_uri', 'login_username', 'login_password', 'login_totp']
        
        # Créer le writer CSV
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        # Écrire chaque credential au format Bitwarden
        for cred in credentials:
            folder = ''
            if self.include_tags and cred['tags']:
                folder = cred['tags'][0]  # Utiliser le premier tag comme dossier
            
            row = {
                'folder': folder,
                'favorite': 'false',
                'type': 'login',
                'name': cred['name'],
                'notes': cred['note'],
                'fields': '',
                'login_uri': cred['website'],
                'login_username': cred['email'],
                'login_password': cred['password'],
                'login_totp': ''  # TOTP non disponible
            }
            
            writer.writerow(row)
        
        # Obtenir le contenu du buffer
        csv_data = output.getvalue()
        output.close()
        
        return csv_data.encode('utf-8')


# Factory pour créer le bon handler selon le format d'export
def get_export_handler(format: str, user: User, **kwargs) -> ExportHandler:
    """
    Factory pour créer le bon handler d'export selon le format.
    
    Paramètres:
    - format: Le format d'export ('firekey', 'csv', 'json', 'bitwarden')
    - user: L'utilisateur pour lequel générer l'export
    - kwargs: Arguments supplémentaires pour le handler (include_tags, include_shared, encrypt, password)
    """
    handlers = {
        'firekey': FireKeyExportHandler,
        'csv': CSVExportHandler,
        'json': JSONExportHandler,
        'bitwarden': BitwardenCSVExportHandler
    }
    
    if format not in handlers:
        raise ValueError(f"Format d'export non pris en charge: {format}")
    
    # Créer le handler avec les arguments appropriés
    if format == 'firekey':
        return handlers[format](
            user,
            include_tags=kwargs.get('include_tags', True),
            include_shared=kwargs.get('include_shared', False),
            encrypt=kwargs.get('encrypt', True),
            password=kwargs.get('password')
        )
    else:
        return handlers[format](
            user,
            include_tags=kwargs.get('include_tags', True),
            include_shared=kwargs.get('include_shared', False)
        )