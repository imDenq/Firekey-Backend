from rest_framework import serializers
from .models_e2e import CredentialE2E, UserKeyDerivation
from .e2e_crypto import E2ECryptoManager
import json

class UserKeyDerivationSerializer(serializers.ModelSerializer):
    """Serializer pour les paramètres de dérivation de clé"""
    
    class Meta:
        model = UserKeyDerivation
        fields = ['salt', 'iterations', 'algorithm', 'search_salt']
        read_only_fields = ['salt', 'search_salt']

class EncryptedDataField(serializers.Field):
    """
    Field personnalisé pour valider les données chiffrées côté client
    """
    
    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError("Les données chiffrées doivent être un objet JSON")
        
        is_valid, error_msg = E2ECryptoManager.validate_encrypted_payload(data)
        if not is_valid:
            raise serializers.ValidationError(f"Payload de chiffrement invalide: {error_msg}")
        
        return data
    
    def to_representation(self, value):
        if isinstance(value, str):
            try:
                import json
                return json.loads(value)
            except:
                return {"ciphertext": value}  # Fallback pour compatibilité
        return value

class CredentialE2ESerializer(serializers.ModelSerializer):
    """
    Serializer pour credentials chiffrés de bout en bout
    """
    
    # Champs pour recevoir les données chiffrées du client
    encrypted_name = EncryptedDataField()
    encrypted_website = EncryptedDataField(required=False)
    encrypted_email = EncryptedDataField(required=False)
    encrypted_password = EncryptedDataField()
    encrypted_notes = EncryptedDataField(required=False)
    
    # Champs pour les hashs de recherche
    search_hashes = serializers.DictField(write_only=True, required=False)
    
    class Meta:
        model = CredentialE2E
        fields = [
            'id', 'encrypted_name', 'encrypted_website', 'encrypted_email',
            'encrypted_password', 'encrypted_notes', 'search_hashes',
            'is_sensitive', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate(self, attrs):
        """
        Validation globale des données
        """
        # Valider que les hashs de recherche sont cohérents
        search_hashes = attrs.get('search_hashes', {})
        
        # Le client doit fournir des hashs pour la recherche
        if not search_hashes:
            raise serializers.ValidationError(
                "Les hashs de recherche sont requis pour permettre la recherche"
            )
        
        return attrs
    
    def create(self, validated_data):
        """
        Création d'un nouveau credential E2E
        """
        search_hashes = validated_data.pop('search_hashes', {})
        
        # Convertir les objets chiffrés en JSON pour stockage
        for field in ['encrypted_name', 'encrypted_website', 'encrypted_email', 'encrypted_password', 'encrypted_notes']:
            if field in validated_data and isinstance(validated_data[field], dict):
                validated_data[field] = json.dumps(validated_data[field])
        
        # Créer le credential
        credential = CredentialE2E.objects.create(
            user=self.context['request'].user,
            name_search_hash=search_hashes.get('name', ''),
            website_search_hash=search_hashes.get('website', ''),
            email_search_hash=search_hashes.get('email', ''),
            **validated_data
        )
        
        return credential