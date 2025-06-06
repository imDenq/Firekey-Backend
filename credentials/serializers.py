# credentials/serializers.py
from rest_framework import serializers
from .models import Credential, CredentialShare, Tag
from datetime import timedelta
from django.utils import timezone

class TagSerializer(serializers.ModelSerializer):
    """Serializer pour les tags"""
    credential_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Tag
        fields = ['id', 'name', 'color', 'created_at', 'credential_count']
        read_only_fields = ['id', 'created_at', 'credential_count']
    
    def get_credential_count(self, obj):
        """Renvoie le nombre de credentials associés à ce tag"""
        return obj.credentials.count()

class CredentialSerializer(serializers.ModelSerializer):
    # Champ en écriture uniquement pour accepter le mot de passe en clair depuis le frontend.
    password = serializers.CharField(write_only=True, required=False, default='')
    tags = TagSerializer(many=True, read_only=True)

    tag_ids = serializers.PrimaryKeyRelatedField(
        many=True, 
        write_only=True, 
        queryset=Tag.objects.all(),
        required=False,
        source='tags'
    )

    class Meta:
        model = Credential
        fields = [
            'id', 'user', 'name', 'website', 'email',
            'note', 'is_sensitive', 'password_encrypted', 'password',
            'created_at', 'updated_at', 'tags', 'tag_ids'
        ]
        read_only_fields = ['user', 'password_encrypted', 'created_at', 'updated_at']
    
    def create(self, validated_data):
        """
        Surcharger la méthode create pour gérer correctement le mot de passe
        """
        password = validated_data.pop('password', '')
        
        return super().create(validated_data)

class CredentialShareSerializer(serializers.ModelSerializer):
    """Serializer pour la création et la gestion des liens de partage"""
    # Champ en entrée uniquement pour définir la durée d'expiration en jours
    expires_in_days = serializers.IntegerField(write_only=True, min_value=1, max_value=30, default=1, required=False)
    # ID du credential à partager
    credential_id = serializers.IntegerField(write_only=True, required=False)
    # ID de partage formatté pour l'URL
    share_id = serializers.SerializerMethodField()
    # Informations sur le credential partagé
    credential = serializers.SerializerMethodField()
    
    class Meta:
        model = CredentialShare
        fields = [
            'id', 'share_id', 'credential_id', 'credential', 'expires_in_days', 
            'max_access_count', 'access_count', 'created_at', 
            'expires_at', 'remaining_accesses', 'is_expired'
        ]
        read_only_fields = ['id', 'share_id', 'created_at', 'access_count', 'remaining_accesses', 'is_expired']
    
    def get_share_id(self, obj):
        """Format l'ID pour l'URL de partage"""
        return f"{obj.id}/{obj.access_key}"
    
    def get_credential(self, obj):
        """Récupère les informations de base du credential partagé"""
        credential = obj.credential
        return {
            'id': credential.id,
            'name': credential.name,
            'website': credential.website,
            'email': credential.email
        }
    
    def create(self, validated_data):
        # Récupérer le credential_id et le supprimer des données validées
        credential_id = validated_data.pop('credential_id', None)
        if credential_id is None:
            raise serializers.ValidationError({"credential_id": "Ce champ est requis."})

        # Récupérer le nombre de jours d'expiration
        expires_in_days = validated_data.pop('expires_in_days', 1)  # Par défaut 1 jour si non spécifié

        # On vérifie si expires_at est déjà fourni, sinon on le calcule
        if 'expires_at' not in validated_data:
            # Calculer la date d'expiration
            expires_at = timezone.now() + timedelta(days=expires_in_days)
        else:
            # Utiliser la date fournie
            expires_at = validated_data.pop('expires_at')

        try:
            # Vérifier que le credential existe et appartient à l'utilisateur actuel
            credential = Credential.objects.get(id=credential_id, user=self.context['request'].user)
        except Credential.DoesNotExist:
            raise serializers.ValidationError({"credential_id": "Ce credential n'existe pas ou ne vous appartient pas."})

        # Vérifier que max_access_count est une valeur raisonnable
        if 'max_access_count' in validated_data and validated_data['max_access_count'] is not None:
            # Limiter la valeur à 1000 pour éviter des erreurs de dépassement
            if validated_data['max_access_count'] > 1000:
                validated_data['max_access_count'] = 1000

        # Créer le partage
        share = CredentialShare.objects.create(
            credential=credential,
            creator=self.context['request'].user,
            expires_at=expires_at,
            max_access_count=validated_data.get('max_access_count')
        )

        return share
        
    def update(self, instance, validated_data):
        """
        Mise à jour d'un CredentialShare existant.
        Permet de modifier la date d'expiration et le nombre maximum d'accès.
        """
        # Mise à jour de la date d'expiration si fournie
        if 'expires_at' in validated_data:
            instance.expires_at = validated_data.get('expires_at', instance.expires_at)
        
        # Gestion du nombre maximum d'accès
        if 'max_access_count' in validated_data:
            # Si la valeur est None, cela signifie pas de limite
            instance.max_access_count = validated_data.get('max_access_count')
            
        instance.save()
        return instance
    
