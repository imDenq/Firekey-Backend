# importexport/serializers.py
from rest_framework import serializers
from .models import ImportHistory, ExportHistory, ImportFileStatus
from credentials.models import Credential, Tag

class ImportHistorySerializer(serializers.ModelSerializer):
    """Serializer pour l'historique des imports"""
    username = serializers.SerializerMethodField()
    
    class Meta:
        model = ImportHistory
        fields = ['id', 'username', 'source', 'file_name', 'credentials_imported', 
                  'credentials_skipped', 'credentials_merged', 'status', 
                  'error_message', 'created_at']
        read_only_fields = ['id', 'created_at']
    
    def get_username(self, obj):
        return obj.user.username

class ExportHistorySerializer(serializers.ModelSerializer):
    """Serializer pour l'historique des exports"""
    username = serializers.SerializerMethodField()
    
    class Meta:
        model = ExportHistory
        fields = ['id', 'username', 'format', 'encrypted', 'credentials_exported', 
                  'status', 'error_message', 'created_at']
        read_only_fields = ['id', 'created_at']
    
    def get_username(self, obj):
        return obj.user.username

class ImportFileStatusSerializer(serializers.ModelSerializer):
    """Serializer pour le statut d'importation d'un fichier"""
    
    class Meta:
        model = ImportFileStatus
        fields = ['id', 'file_id', 'source', 'file_name', 'analysis_status', 
                  'total_credentials', 'new_credentials', 'duplicate_credentials', 
                  'conflict_credentials', 'error_message', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

class ImportPreviewCredentialSerializer(serializers.Serializer):
    """Serializer pour la prévisualisation des credentials à importer"""
    id = serializers.CharField(required=False)  # ID temporaire pour le front
    name = serializers.CharField()
    website = serializers.CharField(required=False, allow_blank=True)
    email = serializers.CharField(required=False, allow_blank=True)
    username = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(required=False, allow_blank=True, write_only=True)  # Jamais exposé
    notes = serializers.CharField(required=False, allow_blank=True)
    status = serializers.ChoiceField(choices=['new', 'duplicate', 'conflict'], default='new')
    strength = serializers.ChoiceField(choices=['weak', 'medium', 'strong'], default='medium')
    duplicated = serializers.BooleanField(default=False)
    tags = serializers.ListField(child=serializers.CharField(), required=False, default=[])
    
    def to_representation(self, instance):
        """Personnalisé pour masquer le mot de passe dans les réponses"""
        data = super().to_representation(instance)
        # Supprimer le mot de passe de la représentation
        if 'password' in data:
            del data['password']
        return data

class ImportRequestSerializer(serializers.Serializer):
    """Serializer pour une requête d'import"""
    source = serializers.CharField(required=True)
    file_id = serializers.CharField(required=True)
    password = serializers.CharField(required=False, allow_blank=True)
    merge_strategy = serializers.ChoiceField(
        choices=['skip', 'rename', 'overwrite', 'smart_merge'],
        default='smart_merge'
    )

class ExportRequestSerializer(serializers.Serializer):
    """Serializer pour une requête d'export"""
    format = serializers.ChoiceField(
        choices=['firekey', 'csv', 'json', 'bitwarden'],
        default='firekey'
    )
    encrypt = serializers.BooleanField(default=True)
    password = serializers.CharField(required=False, allow_blank=True)
    include_tags = serializers.BooleanField(default=True)
    include_shared = serializers.BooleanField(default=False)
    
    def validate(self, data):
        """Validation personnalisée"""
        format = data.get('format')
        encrypt = data.get('encrypt')
        password = data.get('password', '')
        
        # Si encrypt est True et le format est 'firekey', le mot de passe est obligatoire
        if format == 'firekey' and encrypt and not password:
            raise serializers.ValidationError({
                "password": "Un mot de passe est requis pour un export FireKey chiffré"
            })
        
        # Si le format n'est pas 'firekey', on ignore l'option encrypt
        if format != 'firekey':
            data['encrypt'] = False
        
        return data

class CredentialExportSerializer(serializers.ModelSerializer):
    """Serializer pour l'export des credentials"""
    tags = serializers.SerializerMethodField()
    
    class Meta:
        model = Credential
        fields = ['id', 'name', 'website', 'email', 'note', 'is_sensitive', 'created_at', 'updated_at', 'tags']
    
    def get_tags(self, obj):
        return [tag.name for tag in obj.tags.all()]