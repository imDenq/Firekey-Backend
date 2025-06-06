# importexport/password_strength.py
import re
import math

def evaluate_password_strength(password: str) -> str:
    """
    Évalue la force d'un mot de passe et retourne 'weak', 'medium' ou 'strong'
    
    Critères:
    - Faible: moins de 8 caractères, ou uniquement des lettres/chiffres
    - Moyen: au moins 8 caractères avec un mélange de lettres/chiffres
    - Fort: au moins 12 caractères avec mélange de lettres majuscules/minuscules, 
            chiffres et caractères spéciaux
    """
    if not password:
        return 'weak'
    
    # Calcul du score de base sur l'entropie
    score = 0
    
    # Longueur (facteur le plus important)
    length = len(password)
    if length < 8:
        score += 10
    elif length < 12:
        score += 20
    elif length < 16:
        score += 30
    else:
        score += 40
    
    # Variété de caractères
    has_lowercase = bool(re.search(r'[a-z]', password))
    has_uppercase = bool(re.search(r'[A-Z]', password))
    has_digits = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    
    # Ajouter des points pour chaque type de caractère
    char_types = 0
    if has_lowercase:
        char_types += 1
    if has_uppercase:
        char_types += 1
    if has_digits:
        char_types += 1
    if has_special:
        char_types += 1
    
    score += char_types * 10
    
    # Vérifier les modèles courants (séquences, répétitions)
    
    # Séquences (123, abc)
    seq_regex = r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789|890)'
    if re.search(seq_regex, password.lower()):
        score -= 10
    
    # Répétitions (aa, 111)
    if re.search(r'(.)\1{2,}', password):
        score -= 10
    
    # Mots de passe courants et mots du dictionnaire
    common_passwords = ['password', '123456', 'qwerty', 'admin', 'welcome', 
                        'login', 'abc123', 'letmein', 'master', 'hello', 
                        'monkey', 'password123', 'test']
    
    if password.lower() in common_passwords:
        score -= 30
    
    # Mots inversés
    if password.lower()[::-1] in common_passwords:
        score -= 20
    
    # Date potentielle (ex: 19851025)
    if re.match(r'^\d{8}$', password) and (1900 <= int(password[:4]) <= 2023):
        score -= 15
    
    # Évaluation finale
    if score < 30:
        return 'weak'
    elif score < 60:
        return 'medium'
    else:
        return 'strong'