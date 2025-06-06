# security/password_utils.py
import re
import hashlib
from datetime import datetime, timedelta
from django.utils import timezone
from credentials.crypto_utils import decrypt_password
from .models import PasswordStrength

def evaluate_password_strength(plaintext_password):
    """
    Évalue la force d'un mot de passe en texte clair
    Retourne un tuple (strength, score) où :
      - strength est l'une des valeurs de PasswordStrength
      - score est un entier entre 0 et 100
    """
    if not plaintext_password:
        return PasswordStrength.WEAK, 0
    
    # Longueur minimale
    if len(plaintext_password) < 8:
        return PasswordStrength.WEAK, max(10, len(plaintext_password) * 5)
    
    # Score initial basé sur la longueur (jusqu'à 50 points)
    score = min(50, len(plaintext_password) * 4)
    
    # Vérifier les critères de complexité
    has_lowercase = bool(re.search(r'[a-z]', plaintext_password))
    has_uppercase = bool(re.search(r'[A-Z]', plaintext_password))
    has_digit = bool(re.search(r'\d', plaintext_password))
    has_special_char = bool(re.search(r'[^A-Za-z0-9]', plaintext_password))
    
    # Ajouter des points pour chaque critère rempli
    if has_lowercase:
        score += 10
    if has_uppercase:
        score += 10
    if has_digit:
        score += 10
    if has_special_char:
        score += 20
    
    # Pénalités pour motifs communs
    common_patterns = [
        r'123', r'abc', r'qwerty', r'password', r'admin', r'welcome',
        r'letmein', r'monkey', r'dragon', r'baseball', r'football',
        r'shadow', r'master', r'666', r'654321', r'121212', r'000000',
        r'sunshine', r'princess', r'azerty', r'trustno1', r'whatever'
    ]
    
    for pattern in common_patterns:
        if pattern in plaintext_password.lower():
            score -= 10
    
    # Pénalités pour répétitions
    if re.search(r'(.)\1\1+', plaintext_password):  # Caractère répété 3+ fois
        score -= 10
    
    # Pénalités pour séquences
    if re.search(r'(012|123|234|345|456|567|678|789)', plaintext_password):
        score -= 10
    
    # Limiter le score entre 0 et 100
    score = max(0, min(100, score))
    
    # Déterminer la force en fonction du score
    if score < 40:
        return PasswordStrength.WEAK, score
    elif score < 70:
        return PasswordStrength.MEDIUM, score
    else:
        return PasswordStrength.STRONG, score

def is_old_password(credential, days_threshold=90):
    """
    Vérifie si un credential n'a pas été mis à jour depuis un certain nombre de jours
    """
    # Si la date de mise à jour n'est pas disponible, on utilise la date de création
    last_update = getattr(credential, 'updated_at', None) or credential.created_at
    threshold_date = timezone.now() - timedelta(days=days_threshold)
    
    return last_update < threshold_date

def find_duplicate_passwords(credentials):
    """
    Identifie les credentials ayant des mots de passe identiques
    Retourne un dictionnaire où les clés sont les hashs des mots de passe
    et les valeurs sont des listes de credentials
    """
    password_map = {}
    duplicates = {}
    
    for credential in credentials:
        try:
            # Déchiffrer le mot de passe
            plaintext = decrypt_password(credential.password_encrypted)
            
            # Utiliser un hash pour comparer (évite de stocker les mots de passe en mémoire)
            pwd_hash = hashlib.sha256(plaintext.encode()).hexdigest()
            
            # Si le hash existe déjà, c'est un doublon
            if pwd_hash in password_map:
                # Ajouter le premier credential s'il n'est pas déjà dans les duplicats
                if pwd_hash not in duplicates:
                    duplicates[pwd_hash] = [password_map[pwd_hash]]
                
                # Ajouter le credential actuel
                duplicates[pwd_hash].append(credential)
            else:
                # Sinon, ajouter au map
                password_map[pwd_hash] = credential
        except Exception:
            # Ignorer les erreurs de déchiffrement
            continue
    
    return duplicates

def audit_user_security(user):
    """
    Effectue un audit complet de la sécurité des credentials d'un utilisateur
    Retourne un dictionnaire contenant les résultats de l'audit
    """
    from credentials.models import Credential
    from .models import SecurityAudit, CredentialStrengthCache
    
    # Récupérer tous les credentials de l'utilisateur
    credentials = Credential.objects.filter(user=user)
    total_credentials = len(credentials)
    
    # Initialiser les compteurs
    weak_passwords = []
    old_passwords = []
    
    # Pour chaque credential, évaluer sa force
    for credential in credentials:
        try:
            # Déchiffrer le mot de passe
            plaintext = decrypt_password(credential.password_encrypted)
            
            # Évaluer la force
            strength, score = evaluate_password_strength(plaintext)
            
            # Mettre à jour ou créer le cache de force
            CredentialStrengthCache.objects.update_or_create(
                credential=credential,
                defaults={
                    'strength': strength,
                    'score': score
                }
            )
            
            # Vérifier si le mot de passe est faible
            if strength == PasswordStrength.WEAK:
                weak_passwords.append(credential.id)
            
            # Vérifier si le mot de passe est ancien
            if is_old_password(credential):
                old_passwords.append(credential.id)
                
        except Exception as e:
            # Ignorer les erreurs de déchiffrement
            print(f"Erreur lors de l'évaluation du credential {credential.id}: {str(e)}")
    
    # Trouver les mots de passe dupliqués
    duplicates = find_duplicate_passwords(credentials)
    duplicate_ids = []
    
    for pwd_hash, creds in duplicates.items():
        for cred in creds:
            duplicate_ids.append(cred.id)
    
    # Calculer le score de sécurité
    security_score = calculate_security_score(
        total_credentials, 
        len(weak_passwords), 
        len(duplicate_ids), 
        len(old_passwords)
    )
    
    # Créer l'audit
    audit = SecurityAudit.objects.create(
        user=user,
        security_score=security_score,
        weak_passwords_count=len(weak_passwords),
        duplicate_passwords_count=len(duplicate_ids),
        old_passwords_count=len(old_passwords),
        total_credentials_count=total_credentials,
        audit_details={
            'weak_passwords': weak_passwords,
            'duplicate_passwords': duplicate_ids,
            'old_passwords': old_passwords
        }
    )
    
    return {
        'audit_id': audit.id,
        'security_score': security_score,
        'total_credentials': total_credentials,
        'weak_passwords': weak_passwords,
        'duplicate_passwords': duplicate_ids,
        'old_passwords': old_passwords
    }

def calculate_security_score(total_credentials, weak_count, duplicate_count, old_count):
    """
    Calcule un score de sécurité global basé sur divers facteurs
    Retourne un entier entre 0 et 100
    """
    if total_credentials == 0:
        return 0
    
    # Base score: 100 points
    score = 100
    
    # Pénalités
    # - Mots de passe faibles: -10 points chacun
    score -= weak_count * 10
    
    # - Mots de passe dupliqués: -15 points chacun
    score -= duplicate_count * 15
    
    # - Mots de passe anciens: -5 points chacun
    score -= old_count * 5
    
    # Bonus pour le nombre de credentials (max +10)
    score += min(10, total_credentials)
    
    # Limiter le score entre 0 et 100
    return max(0, min(100, score))