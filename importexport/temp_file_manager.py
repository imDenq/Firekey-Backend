# importexport/temp_file_manager.py
import os
import hashlib
import hmac
import base64
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any
from django.conf import settings
from django.core.files.storage import default_storage
from django.utils import timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import logging

logger = logging.getLogger(__name__)

class TempFileManager:
    """
    Gestionnaire de fichiers temporaires chiffrés pour les imports
    
    Fonctionnalités:
    - Chiffrement AES-256-GCM des fichiers temporaires
    - Suppression automatique après expiration
    - Nettoyage périodique des fichiers expirés
    - Gestion sécurisée des clés de chiffrement
    """
    
    def __init__(self):
        # Répertoire de stockage des fichiers temporaires chiffrés
        self.temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp_encrypted')
        self._ensure_temp_dir()
        
        # Clé maître pour le chiffrement (doit être en configuration)
        self.master_key = self._get_master_key()
    
    def _ensure_temp_dir(self):
        """S'assurer que le répertoire temporaire existe"""
        os.makedirs(self.temp_dir, mode=0o700, exist_ok=True)
    
    def _get_master_key(self) -> bytes:
        """
        Récupère la clé maître pour le chiffrement des fichiers temporaires
        En production, cette clé doit être stockée de manière sécurisée
        """
        # En production, utiliser une vraie clé depuis les variables d'environnement
        master_key_b64 = getattr(settings, 'TEMP_FILE_ENCRYPTION_KEY', None)
        
        if master_key_b64:
            try:
                return base64.b64decode(master_key_b64)
            except Exception:
                logger.warning("Clé de chiffrement invalide, génération d'une nouvelle clé")
        
        # Générer une nouvelle clé si aucune n'est configurée
        # ATTENTION: En production, cette clé doit être persistante !
        key = os.urandom(32)  # 256 bits
        logger.warning(f"Nouvelle clé générée: {base64.b64encode(key).decode()}")
        logger.warning("IMPORTANT: Configurez TEMP_FILE_ENCRYPTION_KEY dans settings.py")
        return key
    
    def store_encrypted_file(self, file_id: str, file_data: bytes, 
                           metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Store un fichier de manière chiffrée
        
        Args:
            file_id: Identifiant unique du fichier
            file_data: Données du fichier à chiffrer
            metadata: Métadonnées optionnelles (source, filename, etc.)
        
        Returns:
            Chemin du fichier chiffré stocké
        """
        try:
            # Générer un salt unique pour ce fichier
            salt = os.urandom(16)
            
            # Dériver une clé spécifique pour ce fichier
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            file_key = kdf.derive(self.master_key + file_id.encode())
            
            # Générer un nonce pour GCM
            nonce = os.urandom(12)  # 96 bits pour GCM
            
            # Chiffrer les données
            cipher = Cipher(algorithms.AES(file_key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Chiffrer les métadonnées si présentes
            metadata_json = ""
            if metadata:
                import json
                metadata_json = json.dumps(metadata)
            
            # Données à chiffrer: métadonnées + séparateur + données du fichier
            data_to_encrypt = f"{metadata_json}\n---SEPARATOR---\n".encode() + file_data
            
            ciphertext = encryptor.update(data_to_encrypt) + encryptor.finalize()
            
            # Construire l'en-tête du fichier chiffré
            header = {
                'version': '1.0',
                'file_id': file_id,
                'timestamp': timezone.now().isoformat(),
                'salt': base64.b64encode(salt).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'tag': base64.b64encode(encryptor.tag).decode()
            }
            
            # Sérialiser l'en-tête
            import json
            header_json = json.dumps(header).encode()
            
            # Construire le fichier final
            # Format: [4 bytes taille header][header JSON][données chiffrées]
            header_size = len(header_json)
            encrypted_file_data = header_size.to_bytes(4, byteorder='big')
            encrypted_file_data += header_json
            encrypted_file_data += ciphertext
            
            # Chemin du fichier chiffré
            encrypted_path = os.path.join(self.temp_dir, f"{file_id}.enc")
            
            # Écrire le fichier chiffré
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_file_data)
            
            logger.info(f"Fichier chiffré stocké: {encrypted_path}")
            return encrypted_path
            
        except Exception as e:
            logger.error(f"Erreur lors du stockage chiffré: {str(e)}")
            raise Exception(f"Impossible de stocker le fichier chiffré: {str(e)}")
    
    def load_encrypted_file(self, file_id: str) -> tuple[bytes, Dict[str, Any]]:
        """
        Charge et déchiffre un fichier temporaire
        
        Args:
            file_id: Identifiant du fichier
            
        Returns:
            Tuple (données_déchiffrées, métadonnées)
        """
        try:
            encrypted_path = os.path.join(self.temp_dir, f"{file_id}.enc")
            
            if not os.path.exists(encrypted_path):
                raise FileNotFoundError(f"Fichier temporaire non trouvé: {file_id}")
            
            # Lire le fichier chiffré
            with open(encrypted_path, 'rb') as f:
                # Lire la taille de l'en-tête
                header_size_bytes = f.read(4)
                if len(header_size_bytes) != 4:
                    raise Exception("Fichier corrompu: en-tête invalide")
                
                header_size = int.from_bytes(header_size_bytes, byteorder='big')
                
                # Lire l'en-tête
                header_json = f.read(header_size)
                if len(header_json) != header_size:
                    raise Exception("Fichier corrompu: en-tête tronqué")
                
                # Lire les données chiffrées
                ciphertext = f.read()
            
            # Désérialiser l'en-tête
            import json
            header = json.loads(header_json.decode())
            
            # Vérifier l'ID du fichier
            if header.get('file_id') != file_id:
                raise Exception("ID de fichier incorrect")
            
            # Récupérer les paramètres de déchiffrement
            salt = base64.b64decode(header['salt'])
            nonce = base64.b64decode(header['nonce'])
            tag = base64.b64decode(header['tag'])
            
            # Reconstruire la clé
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            file_key = kdf.derive(self.master_key + file_id.encode())
            
            # Déchiffrer
            cipher = Cipher(algorithms.AES(file_key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Séparer les métadonnées des données du fichier
            separator = b"\n---SEPARATOR---\n"
            if separator in decrypted_data:
                metadata_part, file_data = decrypted_data.split(separator, 1)
                try:
                    metadata = json.loads(metadata_part.decode()) if metadata_part else {}
                except:
                    metadata = {}
            else:
                file_data = decrypted_data
                metadata = {}
            
            return file_data, metadata
            
        except Exception as e:
            logger.error(f"Erreur lors du chargement du fichier chiffré {file_id}: {str(e)}")
            raise Exception(f"Impossible de charger le fichier: {str(e)}")
    
    def delete_file(self, file_id: str):
        """Supprime définitivement un fichier temporaire"""
        try:
            encrypted_path = os.path.join(self.temp_dir, f"{file_id}.enc")
            
            if os.path.exists(encrypted_path):
                # Écraser le fichier avec des données aléatoires avant suppression
                self._secure_delete(encrypted_path)
                logger.info(f"Fichier temporaire supprimé: {file_id}")
            else:
                logger.warning(f"Fichier temporaire déjà supprimé: {file_id}")
                
        except Exception as e:
            logger.error(f"Erreur lors de la suppression du fichier {file_id}: {str(e)}")
    
    def _secure_delete(self, file_path: str):
        """
        Suppression sécurisée d'un fichier (écrasement + suppression)
        """
        try:
            if not os.path.exists(file_path):
                return
            
            # Obtenir la taille du fichier
            file_size = os.path.getsize(file_path)
            
            # Écraser le fichier avec des données aléatoires (3 passes)
            with open(file_path, 'r+b') as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())  # Force l'écriture sur disque
            
            # Supprimer le fichier
            os.remove(file_path)
            
        except Exception as e:
            logger.error(f"Erreur lors de la suppression sécurisée: {str(e)}")
            # Tenter une suppression normale en dernier recours
            try:
                os.remove(file_path)
            except:
                pass
    
    def cleanup_expired_files(self, max_age_hours: int = 1):
        """
        Nettoie les fichiers temporaires expirés
        
        Args:
            max_age_hours: Âge maximum en heures avant suppression
        """
        try:
            cutoff_time = timezone.now() - timedelta(hours=max_age_hours)
            deleted_count = 0
            
            if not os.path.exists(self.temp_dir):
                return deleted_count
            
            for filename in os.listdir(self.temp_dir):
                if not filename.endswith('.enc'):
                    continue
                
                file_path = os.path.join(self.temp_dir, filename)
                
                try:
                    # Vérifier l'âge du fichier
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                    file_mtime = timezone.make_aware(file_mtime)
                    
                    if file_mtime < cutoff_time:
                        self._secure_delete(file_path)
                        deleted_count += 1
                        logger.info(f"Fichier expiré supprimé: {filename}")
                        
                except Exception as e:
                    logger.error(f"Erreur lors de la vérification du fichier {filename}: {str(e)}")
            
            logger.info(f"Nettoyage terminé: {deleted_count} fichiers supprimés")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage: {str(e)}")
            return 0
    
    def get_file_info(self, file_id: str) -> Optional[Dict[str, Any]]:
        """
        Récupère les informations d'un fichier sans le déchiffrer complètement
        """
        try:
            encrypted_path = os.path.join(self.temp_dir, f"{file_id}.enc")
            
            if not os.path.exists(encrypted_path):
                return None
            
            # Lire seulement l'en-tête
            with open(encrypted_path, 'rb') as f:
                header_size_bytes = f.read(4)
                if len(header_size_bytes) != 4:
                    return None
                
                header_size = int.from_bytes(header_size_bytes, byteorder='big')
                header_json = f.read(header_size)
                
                if len(header_json) != header_size:
                    return None
            
            import json
            header = json.loads(header_json.decode())
            
            # Ajouter les informations du système de fichiers
            stat = os.stat(encrypted_path)
            header['file_size'] = stat.st_size
            header['created_time'] = datetime.fromtimestamp(stat.st_ctime)
            header['modified_time'] = datetime.fromtimestamp(stat.st_mtime)
            
            return header
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des infos du fichier {file_id}: {str(e)}")
            return None


# Instance globale du gestionnaire
temp_file_manager = TempFileManager()