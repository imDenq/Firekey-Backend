# accounts/serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile, UserSession, DeleteAccountToken

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['fullName', 'language', 'profile_pic', 'two_factor_enabled']
        extra_kwargs = {
            'fullName': {'required': False, 'allow_blank': True},
            'language': {'required': False, 'allow_blank': True},
            'profile_pic': {'required': False, 'allow_null': True},
            'two_factor_enabled': {'required': False}
        }

class UserSerializer(serializers.ModelSerializer):
    # On inclut le profil comme un sous-objet
    profile = UserProfileSerializer(required=False)
    # NOUVEAU: Ajouter le statut E2E
    e2e_status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['username', 'email', 'profile', 'e2e_status']
        extra_kwargs = {
            'username': {'required': False},
            'email': {'required': False}
        }
    
    def get_e2e_status(self, obj):
        """Retourne le statut E2E de l'utilisateur"""
        try:
            return obj.profile.e2e_status
        except UserProfile.DoesNotExist:
            return {
                'available': False,
                'enabled': False,
                'setup_completed': False,
                'activated_at': None
            }

    def update(self, instance, validated_data):
        """
        Surcharger pour mettre à jour les champs du user
        ET les champs du user.profile
        """
        profile_data = validated_data.pop('profile', {})
        
        # Mettre à jour l'utilisateur
        if 'username' in validated_data:
            instance.username = validated_data.get('username')
        if 'email' in validated_data:
            instance.email = validated_data.get('email')
        
        instance.save()

        # Vérifier si le profil existe, sinon le créer
        try:
            profile = instance.profile
        except UserProfile.DoesNotExist:
            profile = UserProfile.objects.create(user=instance)
        
        # Mettre à jour le profil si les données sont fournies
        if profile_data:
            if 'fullName' in profile_data:
                profile.fullName = profile_data.get('fullName', '')
            if 'language' in profile_data:
                profile.language = profile_data.get('language', 'Français')
            if 'profile_pic' in profile_data and profile_data['profile_pic'] is not None:
                profile.profile_pic = profile_data['profile_pic']
            if 'two_factor_enabled' in profile_data:
                profile.two_factor_enabled = profile_data.get('two_factor_enabled')
            
            profile.save()
        
        return instance

class ChangePasswordSerializer(serializers.Serializer):
    """Serializer pour le changement de mot de passe"""
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=8)

class UserSessionSerializer(serializers.ModelSerializer):
    """Serializer pour les sessions utilisateur"""
    is_current = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = UserSession
        fields = ['id', 'ip_address', 'user_agent', 'location', 'device', 'browser', 
                  'created_at', 'last_activity', 'is_current', 'is_active']
        read_only_fields = ['id', 'ip_address', 'user_agent', 'location', 'device', 'browser', 
                           'created_at', 'last_activity', 'is_current']

class TwoFactorSetupSerializer(serializers.Serializer):
    """Serializer pour la configuration de l'authentification à deux facteurs"""
    enable = serializers.BooleanField(required=True)
    code = serializers.CharField(required=False)  # Requis seulement pour l'activation

class TwoFactorLoginSerializer(serializers.Serializer):
    """Serializer pour l'authentification à deux facteurs lors de la connexion"""
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    code = serializers.CharField(required=True, allow_blank=False, trim_whitespace=True)

class TwoFactorAuthSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)
    code = serializers.CharField(required=True, trim_whitespace=True)
    remember = serializers.CharField(required=False, default="false")

class DeleteAccountSerializer(serializers.Serializer):
    """Serializer pour la suppression de compte"""
    password = serializers.CharField(required=True)
    confirm_text = serializers.CharField(required=True)
    
    def validate_confirm_text(self, value):
        if value != "SUPPRIMER":
            raise serializers.ValidationError("Le texte de confirmation doit être 'SUPPRIMER'")
        return value