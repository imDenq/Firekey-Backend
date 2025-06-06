import os
import hashlib
import hmac
import base64
import json
from typing import Dict, Optional, Union, Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from django.conf import settings
from django.utils import timezone

class E2ECryptoManager:
    """
    Gestionnaire de chiffrement de bout en bout
    Gère le chiffrement côté client et la validation côté serveur
    """
    
    CURRENT_VERSION = "1.0"
    SUPPORTED_ALGORITHMS = ["AES-256-GCM"]
    
    @staticmethod
    def validate_encrypted_payload(payload: Dict) -> Tuple[bool, str]:
        """
        Valide qu'un payload est correctement chiffré côté client
        Retourne (is_valid, error_message)
        """
        required_fields = ['ciphertext', 'iv', 'tag', 'algorithm', 'version']
        
        for field in required_fields:
            if field not in payload:
                return False, f"Champ manquant: {field}"
        
        # Vérifier l'algorithme
        if payload['algorithm'] not in E2ECryptoManager.SUPPORTED_ALGORITHMS:
            return False, f"Algorithme non supporté: {payload['algorithm']}"
        
        # Vérifier la version
        if payload['version'] != E2ECryptoManager.CURRENT_VERSION:
            return False, f"Version non supportée: {payload['version']}"
        
        # Vérifier que les données sont bien en base64
        try:
            base64.b64decode(payload['ciphertext'])
            base64.b64decode(payload['iv'])
            base64.b64decode(payload['tag'])
        except Exception:
            return False, "Données base64 invalides"
        
        return True, ""
    
    @staticmethod
    def generate_search_hash(search_term: str, user_salt: str) -> str:
        """
        Génère un hash de recherche pour permettre la recherche
        sans révéler le contenu original
        """
        if not search_term or not search_term.strip():
            return ""
        
        # Normaliser le terme de recherche
        normalized = search_term.lower().strip()
        
        # Générer le hash avec le salt utilisateur
        combined = f"{normalized}{user_salt}"
        hash_obj = hashlib.sha256(combined.encode('utf-8'))
        
        return hash_obj.hexdigest()[:32]  # Tronquer pour éviter les collisions intentionnelles
    
    @staticmethod
    def validate_client_derivation_params(params: Dict) -> Tuple[bool, str]:
        """
        Valide les paramètres de dérivation de clé côté client
        """
        required_params = ['salt', 'iterations', 'algorithm']
        
        for param in required_params:
            if param not in params:
                return False, f"Paramètre manquant: {param}"
        
        # Valider le nombre d'itérations (minimum pour la sécurité)
        if params['iterations'] < 100000:
            return False, "Nombre d'itérations insuffisant (minimum 100000)"
        
        # Valider l'algorithme
        if params['algorithm'] not in ['PBKDF2-SHA256']:
            return False, f"Algorithme de dérivation non supporté: {params['algorithm']}"
        
        return True, ""