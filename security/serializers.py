# security/serializers.py
from rest_framework import serializers
from .models import SecurityAudit, CredentialStrengthCache, AuditLogEntry
from credentials.models import Credential
from credentials.serializers import CredentialSerializer

class CredentialStrengthSerializer(serializers.ModelSerializer):
    """Serializer pour les informations de force d'un credential"""
    credential = CredentialSerializer(read_only=True)
    
    class Meta:
        model = CredentialStrengthCache
        fields = ['credential', 'strength', 'score', 'last_updated']

# Dans security/serializers.py

class CredentialWithStrengthSerializer(serializers.ModelSerializer):
    """Serializer pour les credentials avec leurs informations de force"""
    strength = serializers.SerializerMethodField()
    score = serializers.SerializerMethodField()
    
    class Meta:
        model = Credential
        fields = [
            'id', 'name', 'website', 'email', 'note',
            'is_sensitive', 'strength', 'score'
        ]
        # Retirez 'created_at' de la liste des champs
    
    def get_strength(self, obj):
        """Obtient la force du mot de passe"""
        try:
            return obj.strength_cache.strength
        except (AttributeError, CredentialStrengthCache.DoesNotExist):
            return "unknown"
    
    def get_score(self, obj):
        """Obtient le score numérique de la force du mot de passe"""
        try:
            return obj.strength_cache.score
        except (AttributeError, CredentialStrengthCache.DoesNotExist):
            return 0

class SecurityAuditSerializer(serializers.ModelSerializer):
    """Serializer pour les audits de sécurité"""
    weak_passwords = serializers.SerializerMethodField()
    duplicate_passwords = serializers.SerializerMethodField()
    old_passwords = serializers.SerializerMethodField()
    
    class Meta:
        model = SecurityAudit
        fields = [
            'id', 'created_at', 'security_score', 'weak_passwords_count',
            'duplicate_passwords_count', 'old_passwords_count',
            'total_credentials_count', 'weak_passwords',
            'duplicate_passwords', 'old_passwords'
        ]
    
    def get_weak_passwords(self, obj):
        """Récupère les credentials faibles avec leurs détails"""
        weak_ids = obj.audit_details.get('weak_passwords', [])
        if not weak_ids:
            return []
        
        credentials = Credential.objects.filter(id__in=weak_ids)
        serializer = CredentialWithStrengthSerializer(credentials, many=True)
        return serializer.data
    
    def get_duplicate_passwords(self, obj):
        """Récupère les credentials avec mots de passe dupliqués"""
        duplicate_ids = obj.audit_details.get('duplicate_passwords', [])
        if not duplicate_ids:
            return []
        
        credentials = Credential.objects.filter(id__in=duplicate_ids)
        serializer = CredentialWithStrengthSerializer(credentials, many=True)
        return serializer.data
    
    def get_old_passwords(self, obj):
        """Récupère les credentials avec mots de passe anciens"""
        old_ids = obj.audit_details.get('old_passwords', [])
        if not old_ids:
            return []
        
        credentials = Credential.objects.filter(id__in=old_ids)
        serializer = CredentialWithStrengthSerializer(credentials, many=True)
        return serializer.data

class AuditLogEntrySerializer(serializers.ModelSerializer):
    """Serializer pour les entrées de journal d'activité"""
    action_name = serializers.CharField(source='get_action_type_display', read_only=True)
    
    class Meta:
        model = AuditLogEntry
        fields = [
            'id', 'action_type', 'action_name', 'action_detail',
            'ip_address', 'device_info', 'created_at', 'related_object_id'
        ]

class SecurityDashboardSerializer(serializers.Serializer):
    """Serializer pour les données du tableau de bord de sécurité"""
    security_score = serializers.IntegerField()
    credentials_count = serializers.IntegerField()
    active_shares_count = serializers.IntegerField()
    total_shares_count = serializers.IntegerField()
    weak_passwords = serializers.ListField(child=serializers.IntegerField())
    duplicate_passwords = serializers.ListField(child=serializers.IntegerField())
    old_passwords = serializers.ListField(child=serializers.IntegerField())
    recent_credentials = serializers.ListField(child=CredentialWithStrengthSerializer())
    last_audit = serializers.DateTimeField(allow_null=True)