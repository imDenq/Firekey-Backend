# accounts/models.py
from django.db import models
from django.contrib.auth.models import User
import uuid
import pyotp
import qrcode
import io
import base64
from django.utils import timezone

def user_profile_pic_path(instance, filename):
    """
    Détermine le chemin où stocker l'image,
    profiles/<user_id>/<nom_du_fichier>
    """
    return f"profiles/{instance.user.id}/{filename}"

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    fullName = models.CharField(max_length=100, blank=True)
    language = models.CharField(max_length=20, default='Français', blank=True)
    profile_pic = models.ImageField(upload_to=user_profile_pic_path, null=True, blank=True)
    
    # Champs pour 2FA
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_secret = models.CharField(max_length=32, blank=True, null=True)
    
    # NOUVEAU: Champs pour E2E
    e2e_enabled = models.BooleanField(default=False)
    e2e_setup_completed = models.BooleanField(default=False)
    e2e_activated_at = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"Profil de {self.user.username}"
    
    def generate_2fa_secret(self):
        """Génère une nouvelle clé secrète pour l'authentification à deux facteurs"""
        self.two_factor_secret = pyotp.random_base32()
        self.save(update_fields=['two_factor_secret'])
        return self.two_factor_secret
    
    def get_2fa_qr_code(self):
        """Génère un QR code pour l'authentification à deux facteurs"""
        if not self.two_factor_secret:
            return None
        
        totp = pyotp.TOTP(self.two_factor_secret)
        uri = totp.provisioning_uri(name=self.user.username, issuer_name="FireKey")
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def verify_2fa_code(self, code):
        """
        Vérifie un code 2FA
        S'assure que le code est bien une chaîne et traite les types numériques
        """
        if not self.two_factor_secret:
            print(f"DEBUG: No two_factor_secret found for user")
            return False
    
        print(f"DEBUG: Raw code received: {code}, type: {type(code)}")
    
        # S'assurer que le code est une chaîne de caractères
        if isinstance(code, (int, float)):
            code = str(int(code))  # Convertir nombre en chaîne
    
        # Nettoyer le code (supprimer les espaces)
        if isinstance(code, str):
            code = code.strip()
            print(f"DEBUG: Code after stripping: '{code}'")
    
        # Vérifier que le code est bien un nombre à 6 chiffres
        if not code or not isinstance(code, str) or not code.isdigit() or len(code) != 6:
            print(f"DEBUG: Code format invalid: {code}, type: {type(code)}")
            return False
    
        try:
            print(f"DEBUG: Using secret: {self.two_factor_secret}")
            totp = pyotp.TOTP(self.two_factor_secret)
            print(f"DEBUG: TOTP object created successfully")
            #  Utiliser verify avec le paramètre valid_window pour accepter des codes +/- 1 minute
            result = totp.verify(code, valid_window=1)
            print(f"DEBUG: TOTP verification result: {result}")
            return result
        except Exception as e:
            print(f"DEBUG: Error in TOTP verification: {str(e)}")
            return False
    
    # NOUVEAU: Méthodes pour E2E
    def enable_e2e(self):
        """Active E2E pour cet utilisateur"""
        self.e2e_enabled = True
        self.e2e_setup_completed = True
        self.e2e_activated_at = timezone.now()
        self.save(update_fields=['e2e_enabled', 'e2e_setup_completed', 'e2e_activated_at'])
    
    def disable_e2e(self):
        """Désactive E2E pour cet utilisateur"""
        self.e2e_enabled = False
        self.e2e_activated_at = None
        self.save(update_fields=['e2e_enabled', 'e2e_activated_at'])
    
    @property
    def e2e_status(self):
        """Retourne le statut E2E complet"""
        # E2E est disponible s'il y a des paramètres de dérivation
        has_derivation = hasattr(self.user, 'key_derivation')
        
        return {
            'available': True,
            'enabled': self.e2e_enabled,
            'setup_completed': self.e2e_setup_completed,
            'activated_at': self.e2e_activated_at.isoformat() if self.e2e_activated_at else None
        }

class UserSession(models.Model):
    """Modèle pour stocker les sessions utilisateur"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    device = models.CharField(max_length=255, blank=True, null=True)
    browser = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    is_current = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-last_activity']
    
    def __str__(self):
        return f"Session de {self.user.username} - {self.created_at.strftime('%d/%m/%Y %H:%M')}"
    
    @property
    def is_active(self):
        """Vérifie si la session est encore active"""
        # Une session est considérée active si la dernière activité date de moins de 30 jours
        return (timezone.now() - self.last_activity).days < 30

# Ce modèle peut être utilisé pour créer un token de vérification lors de la suppression de compte
class DeleteAccountToken(models.Model):
    """Token pour la vérification de suppression de compte"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='delete_token')
    token = models.UUIDField(default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Token de suppression pour {self.user.username}"
    
    @property
    def is_valid(self):
        """Vérifie si le token est encore valide (24h)"""
        return (timezone.now() - self.created_at).total_seconds() < 86400  # 24 heures