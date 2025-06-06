# importexport/import_handlers.py
import csv
import json
import io
import re
import uuid
from typing import Dict, List, Any, Tuple, Optional
import hashlib
import logging
from datetime import datetime
from abc import ABC, abstractmethod
from django.contrib.auth.models import User
from credentials.models import Credential, Tag
from credentials.crypto_utils import encrypt_password
from .password_strength import evaluate_password_strength

logger = logging.getLogger(__name__)

class ImportHandler(ABC):
    """Classe abstraite pour tous les handlers d'import"""
    
    def __init__(self, user: User, file_content: bytes, password: str = None):
        self.user = user
        self.file_content = file_content
        self.password = password
        self.credentials_list = []
        self.stats = {
            'total': 0,
            'new': 0,
            'duplicate': 0,
            'conflict': 0,
            'error': 0
        }
    
    @abstractmethod
    def parse(self) -> List[Dict[str, Any]]:
        """
        Parse le fichier et extrait les credentials.
        Doit être implémentée par chaque handler.
        """
        pass
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analyse les credentials parsés pour détecter les conflits et doublons
        Retourne des statistiques avec la liste des credentials
        """
        try:
            # Parse le fichier pour obtenir la liste des credentials
            self.credentials_list = self.parse()
            self.stats['total'] = len(self.credentials_list)
            
            # Récupère tous les credentials existants pour cet utilisateur
            existing_credentials = list(Credential.objects.filter(user=self.user))
            
            # Pour chaque credential importé, vérifie s'il existe déjà
            for cred in self.credentials_list:
                # Générer un ID temporaire unique pour ce credential (pour le frontend)
                cred['id'] = str(uuid.uuid4())
                
                # Évaluer la force du mot de passe
                if 'password' in cred and cred['password']:
                    cred['strength'] = evaluate_password_strength(cred['password'])
                else:
                    cred['strength'] = 'medium'  # Défaut
                
                # Vérifier les doublons
                is_duplicate = False
                for existing_cred in existing_credentials:
                    # Compare par nom et site web
                    if self._is_duplicate(cred, existing_cred):
                        is_duplicate = True
                        cred['status'] = 'duplicate'
                        cred['duplicated'] = True
                        self.stats['duplicate'] += 1
                        break
                
                if not is_duplicate:
                    cred['status'] = 'new'
                    cred['duplicated'] = False
                    self.stats['new'] += 1
            
            return {
                'credentials': self.credentials_list,
                'stats': self.stats
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse: {str(e)}")
            self.stats['error'] = len(self.credentials_list)
            return {
                'credentials': [],
                'stats': self.stats,
                'error': str(e)
            }
    
    def _is_duplicate(self, imported_cred: Dict[str, Any], existing_cred: Credential) -> bool:
        """
        Détermine si un credential importé est un doublon d'un existant
        """
        # Stratégie 1: Même nom et même site web
        if (imported_cred.get('name') == existing_cred.name and 
            imported_cred.get('website') == existing_cred.website):
            return True
        
        # Stratégie 2: Même site web et même email/username
        if (imported_cred.get('website') and 
            imported_cred.get('website') == existing_cred.website):
            if (imported_cred.get('email') and imported_cred.get('email') == existing_cred.email):
                return True
            if (imported_cred.get('username') and 
                imported_cred.get('username') in existing_cred.note):
                return True
        
        return False
    
    def import_credentials(self, merge_strategy: str = 'smart_merge') -> Dict[str, Any]:
        """
        Importe effectivement les credentials dans la base de données.
        """
        imported = 0
        skipped = 0
        merged = 0
        errors = 0
        imported_credentials = []  # Pour stocker les credentials importés avec leurs vrais IDs
        
        if not self.credentials_list:
            try:
                self.credentials_list = self.parse()
            except Exception as e:
                logger.error(f"Erreur lors du parsing pour l'import: {str(e)}")
                return {
                    'status': 'error',
                    'error': str(e),
                    'imported': 0,
                    'skipped': 0,
                    'merged': 0,
                    'errors': 1,
                    'credentials': []
                }
        
        for cred_data in self.credentials_list:
            try:
                # Recherche de credentials existants similaires
                existing = self._find_existing_credential(cred_data)
                
                if existing and merge_strategy == 'skip':
                    # Ignorer les doublons
                    skipped += 1
                    continue
                
                elif existing and merge_strategy == 'overwrite':
                    # Écraser l'existant
                    updated_cred = self._update_credential(existing, cred_data)
                    merged += 1
                    # Ajouter à la liste avec le vrai ID
                    imported_credentials.append({
                        'id': updated_cred.id,
                        'name': updated_cred.name,
                        'website': updated_cred.website,
                        'email': updated_cred.email,
                        'tags': [{'id': tag.id, 'name': tag.name, 'color': tag.color} for tag in updated_cred.tags.all()]
                    })
                
                elif existing and merge_strategy == 'rename':
                    # Créer un nouveau credential avec un nom différent
                    new_name = f"{cred_data['name']} (Importé {datetime.now().strftime('%d/%m/%Y')})"
                    cred_data['name'] = new_name
                    new_cred = self._create_credential(cred_data)
                    imported += 1
                    # Ajouter à la liste avec le vrai ID
                    imported_credentials.append({
                        'id': new_cred.id,
                        'name': new_cred.name,
                        'website': new_cred.website,
                        'email': new_cred.email,
                        'tags': [{'id': tag.id, 'name': tag.name, 'color': tag.color} for tag in new_cred.tags.all()]
                    })
                
                elif existing and merge_strategy == 'smart_merge':
                    # Fusionner intelligemment les données
                    merged_cred = self._smart_merge(existing, cred_data)
                    merged += 1
                    # Ajouter à la liste avec le vrai ID
                    imported_credentials.append({
                        'id': merged_cred.id,
                        'name': merged_cred.name,
                        'website': merged_cred.website,
                        'email': merged_cred.email,
                        'tags': [{'id': tag.id, 'name': tag.name, 'color': tag.color} for tag in merged_cred.tags.all()]
                    })
                
                else:
                    # Créer un nouveau credential
                    new_cred = self._create_credential(cred_data)
                    imported += 1
                    # Ajouter à la liste avec le vrai ID
                    imported_credentials.append({
                        'id': new_cred.id,
                        'name': new_cred.name,
                        'website': new_cred.website,
                        'email': new_cred.email,
                        'tags': [{'id': tag.id, 'name': tag.name, 'color': tag.color} for tag in new_cred.tags.all()]
                    })
            
            except Exception as e:
                logger.error(f"Erreur lors de l'import d'un credential: {str(e)}")
                errors += 1
        
        return {
            'status': 'success' if errors == 0 else 'partial',
            'imported': imported,
            'skipped': skipped,
            'merged': merged,
            'errors': errors,
            'credentials': imported_credentials  # Retourner les credentials avec leurs vrais IDs
        }
    
    def _find_existing_credential(self, cred_data: Dict[str, Any]) -> Optional[Credential]:
        """
        Cherche si un credential similaire existe déjà.
        """
        # Recherche par nom exact et site web
        if cred_data.get('name') and cred_data.get('website'):
            try:
                return Credential.objects.get(
                    user=self.user, 
                    name=cred_data['name'],
                    website=cred_data['website']
                )
            except Credential.DoesNotExist:
                pass
        
        # Recherche par site web et email
        if cred_data.get('website') and cred_data.get('email'):
            try:
                return Credential.objects.get(
                    user=self.user,
                    website=cred_data['website'],
                    email=cred_data['email']
                )
            except Credential.DoesNotExist:
                pass
        
        return None
    
    def _create_credential(self, cred_data: Dict[str, Any]) -> Credential:
        # Champs obligatoires
        new_cred = Credential(
            user=self.user,
            name=cred_data.get('name', 'Credential sans nom'),
            website=cred_data.get('website', ''),
            email=cred_data.get('email', ''),
            note=cred_data.get('notes', ''),
            is_sensitive=False  # Par défaut non sensible
        )
    
        # Ajouter le nom d'utilisateur dans la note s'il existe
        if cred_data.get('username') and cred_data.get('username') != cred_data.get('email'):
            if new_cred.note:
                new_cred.note += f"\n\nNom d'utilisateur: {cred_data['username']}"
            else:
                new_cred.note = f"Nom d'utilisateur: {cred_data['username']}"
    
        # Chiffrer le mot de passe
        if cred_data.get('password'):
            new_cred.password_encrypted = encrypt_password(cred_data['password'])
        else:
            new_cred.password_encrypted = encrypt_password("ChangezCeMotDePasse")
    
        # Sauvegarder le credential
        new_cred.save()
    
        # IMPORTANT: Stocker le vrai ID pour le retour
        cred_data['real_id'] = new_cred.id
    
        # Ajouter les tags si présents
        if cred_data.get('tags'):
            for tag_name in cred_data['tags']:
                if tag_name:
                    tag, created = Tag.objects.get_or_create(
                        user=self.user,
                        name=tag_name,
                        defaults={'color': '#90caf9'}  # Couleur par défaut
                    )
                    new_cred.tags.add(tag)
    
        return new_cred
    
    def _update_credential(self, existing: Credential, new_data: Dict[str, Any]) -> Credential:
        """
        Met à jour un credential existant avec de nouvelles données.
        """
        # On ne met à jour que les champs non vides
        if new_data.get('name'):
            existing.name = new_data['name']
        
        if new_data.get('website'):
            existing.website = new_data['website']
        
        if new_data.get('email'):
            existing.email = new_data['email']
        
        if new_data.get('notes'):
            existing.note = new_data['notes']
        
        # Mise à jour du mot de passe si présent
        if new_data.get('password'):
            existing.password_encrypted = encrypt_password(new_data['password'])
        
        # Sauvegarde des modifications
        existing.save()
        
        # Ajouter de nouveaux tags si présents
        if new_data.get('tags'):
            for tag_name in new_data['tags']:
                if tag_name:
                    tag, created = Tag.objects.get_or_create(
                        user=self.user,
                        name=tag_name,
                        defaults={'color': '#90caf9'}
                    )
                    existing.tags.add(tag)
        
        return existing
    
    def _smart_merge(self, existing: Credential, new_data: Dict[str, Any]) -> Credential:
        """
        Fusionne intelligemment un credential existant avec de nouvelles données.
        Garde les meilleures informations des deux sources.
        """
        # Nom: Garder le plus long des deux
        if len(new_data.get('name', '')) > len(existing.name):
            existing.name = new_data['name']
        
        # Site web: Garder si l'existant est vide
        if not existing.website and new_data.get('website'):
            existing.website = new_data['website']
        
        # Email: Garder si l'existant est vide
        if not existing.email and new_data.get('email'):
            existing.email = new_data['email']
        
        # Notes: Fusionner intelligemment
        if new_data.get('notes'):
            if existing.note:
                # Éviter les doublons dans les notes
                if new_data['notes'] not in existing.note:
                    existing.note += f"\n\n--- Notes importées ---\n{new_data['notes']}"
            else:
                existing.note = new_data['notes']
        
        # Username: Ajouter à la note s'il n'y est pas déjà
        if new_data.get('username') and new_data.get('username') != new_data.get('email'):
            username_pattern = re.compile(r"Nom d'utilisateur:\s*" + re.escape(new_data['username']), re.IGNORECASE)
            if not username_pattern.search(existing.note):
                if existing.note:
                    existing.note += f"\n\nNom d'utilisateur: {new_data['username']}"
                else:
                    existing.note = f"Nom d'utilisateur: {new_data['username']}"
        
        # Mot de passe: Garder le nouveau s'il est plus fort
        if new_data.get('password'):
            new_strength = evaluate_password_strength(new_data['password'])
            # Si le nouveau mot de passe est fort, on le met à jour
            if new_strength == 'strong':
                existing.password_encrypted = encrypt_password(new_data['password'])
        
        # Sauvegarde
        existing.save()
        
        # Ajouter les nouveaux tags
        if new_data.get('tags'):
            for tag_name in new_data['tags']:
                if tag_name:
                    tag, created = Tag.objects.get_or_create(
                        user=self.user,
                        name=tag_name,
                        defaults={'color': '#90caf9'}
                    )
                    existing.tags.add(tag)
        
        return existing


class CSVImportHandler(ImportHandler):
    """Handler pour l'import de fichiers CSV génériques"""
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse un fichier CSV générique"""
        credentials = []
        try:
            # Décodage du contenu
            content = self.file_content.decode('utf-8-sig')  # Gère le BOM UTF-8
            csv_reader = csv.DictReader(io.StringIO(content))
            
            # Détection des champs
            fieldnames = csv_reader.fieldnames
            if not fieldnames:
                raise ValueError("Le fichier CSV n'a pas d'en-têtes de colonnes")
            
            # Mapper les champs avec des noms standardisés
            field_mapping = self._detect_field_mapping(fieldnames)
            
            for row in csv_reader:
                cred = {}
                
                # Mapper les champs
                for dest_field, source_field in field_mapping.items():
                    if source_field and source_field in row:
                        cred[dest_field] = row[source_field].strip()
                
                # Ne prendre que les lignes qui ont au moins un nom
                if cred.get('name'):
                    credentials.append(cred)
        
        except UnicodeDecodeError:
            # Essayer avec un autre encodage
            try:
                content = self.file_content.decode('latin-1')
                csv_reader = csv.DictReader(io.StringIO(content))
                # Même logique que ci-dessus
                # [...]
            except Exception as e:
                raise ValueError(f"Impossible de décoder le fichier CSV: {str(e)}")
        
        except Exception as e:
            raise ValueError(f"Erreur lors du parsing du fichier CSV: {str(e)}")
        
        return credentials
    
    def _detect_field_mapping(self, fieldnames: List[str]) -> Dict[str, str]:
        """
        Détecte automatiquement la correspondance entre les champs du CSV et nos champs standard.
        """
        mapping = {
            'name': None,
            'website': None,
            'email': None,
            'username': None,
            'password': None,
            'notes': None,
            'tags': None
        }
        
        # Liste de patterns possibles pour chaque champ
        patterns = {
            'name': [r'name', r'titre', r'title', r'nom', r'nom du site'],
            'website': [r'url', r'site', r'website', r'site web', r'web', r'link', r'lien'],
            'email': [r'email', r'courriel', r'mail', r'e-mail'],
            'username': [r'user', r'username', r'utilisateur', r'nom d\'utilisateur', r'login', r'identifiant'],
            'password': [r'pass', r'password', r'mot de passe', r'mdp'],
            'notes': [r'note', r'notes', r'comment', r'comments', r'commentaire', r'commentaires', r'remarques'],
            'tags': [r'tag', r'tags', r'groupe', r'groupes', r'category', r'categories', r'catégorie', r'catégories']
        }
        
        for dest_field, possible_matches in patterns.items():
            for fieldname in fieldnames:
                for pattern in possible_matches:
                    if re.search(pattern, fieldname.lower()):
                        mapping[dest_field] = fieldname
                        break
                if mapping[dest_field]:
                    break
        
        # Heuristiques supplémentaires si certains champs n'ont pas été détectés
        if not mapping['name'] and len(fieldnames) > 0:
            mapping['name'] = fieldnames[0]  # Premier champ = nom par défaut
        
        return mapping


class GooglePasswordManagerImportHandler(ImportHandler):
    """Handler pour l'import de fichiers CSV de Google Password Manager"""
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse un fichier CSV de Google Password Manager"""
        credentials = []
        try:
            # Décodage du contenu
            content = self.file_content.decode('utf-8-sig')
            csv_reader = csv.DictReader(io.StringIO(content))
            
            # Vérification des champs requis pour Google Password Manager
            required_fields = ['name', 'url', 'username', 'password']
            
            fieldnames = csv_reader.fieldnames
            if not fieldnames:
                raise ValueError("Le fichier CSV n'a pas d'en-têtes de colonnes")
            
            # Identifier les champs correspondants
            fields_map = {
                'name': next((f for f in fieldnames if f.lower() in ['name', 'nom']), None),
                'url': next((f for f in fieldnames if f.lower() in ['url', 'website', 'site']), None),
                'username': next((f for f in fieldnames if f.lower() in ['username', 'login', 'email']), None),
                'password': next((f for f in fieldnames if f.lower() in ['password', 'pass', 'mot de passe']), None),
                'note': next((f for f in fieldnames if f.lower() in ['note', 'notes', 'comment']), None)
            }
            
            for row in csv_reader:
                cred = {
                    'name': row.get(fields_map['name'], ''),
                    'website': row.get(fields_map['url'], ''),
                    'username': row.get(fields_map['username'], ''),
                    'password': row.get(fields_map['password'], ''),
                    'notes': row.get(fields_map['note'], '')
                }
                
                # Si le username contient un @, c'est probablement un email
                if '@' in cred['username']:
                    cred['email'] = cred['username']
                
                # Extraire le nom à partir de l'URL si pas de nom
                if not cred['name'] and cred['website']:
                    # Essayer d'extraire un nom à partir de l'URL
                    domain_match = re.search(r'https?://(?:www\.)?([^/]+)', cred['website'])
                    if domain_match:
                        domain = domain_match.group(1)
                        # Extraire la partie principale du domaine
                        parts = domain.split('.')
                        if len(parts) > 1:
                            cred['name'] = parts[-2].capitalize()
                
                # Ne prendre que les credentials qui ont au moins un nom
                if cred['name']:
                    credentials.append(cred)
        
        except Exception as e:
            raise ValueError(f"Erreur lors du parsing du fichier Google Password Manager: {str(e)}")
        
        return credentials
    
class BitwardenImportHandler(ImportHandler):
    """Handler pour l'import de fichiers CSV de Bitwarden/Vaultwarden"""
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse un fichier CSV Bitwarden/Vaultwarden"""
        credentials = []
        try:
            # Décodage du contenu - essayer utf-8 d'abord, puis utf-8-sig si échec
            try:
                content = self.file_content.decode('utf-8')
            except UnicodeDecodeError:
                content = self.file_content.decode('utf-8-sig')
                
            # Détecter et supprimer les caractères BOM si présents
            if content.startswith('\ufeff'):
                content = content[1:]
                
            # Utiliser csv.reader pour analyser le contenu
            csv_reader = csv.DictReader(io.StringIO(content))
            
            # Vérifier les champs spécifiques à Bitwarden
            fieldnames = csv_reader.fieldnames
            if not fieldnames:
                raise ValueError("Le fichier CSV n'a pas d'en-têtes de colonnes")
            
            # Afficher les en-têtes pour le débogage
            logger.info(f"En-têtes du fichier CSV Bitwarden : {fieldnames}")
            
            # Identifier les champs - utiliser une approche flexible pour s'adapter aux différentes versions
            field_mapping = {
                'name': None,
                'url': None,
                'username': None,
                'password': None,
                'notes': None,
                'folder': None
            }
            
            # Créer une correspondance entre les champs du CSV et nos champs standard
            for field in fieldnames:
                field_lower = field.lower()
                if field_lower == 'name':
                    field_mapping['name'] = field
                elif field_lower in ['login_uri', 'uri', 'url', 'website']:
                    field_mapping['url'] = field
                elif field_lower in ['login_username', 'username']:
                    field_mapping['username'] = field
                elif field_lower in ['login_password', 'password']:
                    field_mapping['password'] = field
                elif field_lower in ['notes', 'note']:
                    field_mapping['notes'] = field
                elif field_lower == 'folder':
                    field_mapping['folder'] = field
            
            logger.info(f"Correspondance des champs : {field_mapping}")
            
            # Parcourir les lignes du CSV
            for row in csv_reader:
                # Ignorer les lignes qui ne sont pas de type login si spécifié
                if 'type' in row and row['type'] and row['type'].lower() != 'login':
                    continue
                
                # Créer un credential à partir des champs mappés
                cred = {}
                
                # Extraire les valeurs en utilisant le mapping
                if field_mapping['name'] and field_mapping['name'] in row:
                    cred['name'] = row[field_mapping['name']]
                
                if field_mapping['url'] and field_mapping['url'] in row:
                    cred['website'] = row[field_mapping['url']]
                
                if field_mapping['username'] and field_mapping['username'] in row:
                    cred['username'] = row[field_mapping['username']]
                
                if field_mapping['password'] and field_mapping['password'] in row:
                    cred['password'] = row[field_mapping['password']]
                
                if field_mapping['notes'] and field_mapping['notes'] in row:
                    cred['notes'] = row[field_mapping['notes']]
                
                # Utiliser le dossier comme tag si disponible
                cred['tags'] = []
                if field_mapping['folder'] and field_mapping['folder'] in row and row[field_mapping['folder']]:
                    cred['tags'] = [row[field_mapping['folder']]]
                
                # Si username contient @, c'est probablement un email
                if 'username' in cred and '@' in cred['username']:
                    cred['email'] = cred['username']
                
                # Extraire le nom à partir de l'URL si pas de nom mais URL présente
                if not cred.get('name') and cred.get('website'):
                    try:
                        from urllib.parse import urlparse
                        parsed_url = urlparse(cred['website'])
                        domain = parsed_url.netloc
                        if domain:
                            if domain.startswith('www.'):
                                domain = domain[4:]
                            cred['name'] = domain
                    except Exception:
                        pass
                
                # Ne prendre que les credentials qui ont au moins un nom ou une URL
                if cred.get('name') or cred.get('website'):
                    credentials.append(cred)
                else:
                    logger.warning(f"Credential ignoré car sans nom ni URL: {cred}")
            
            logger.info(f"Nombre de credentials trouvés : {len(credentials)}")
            
        except Exception as e:
            logger.error(f"Erreur lors du parsing du fichier Bitwarden: {str(e)}")
            raise ValueError(f"Erreur lors du parsing du fichier Bitwarden: {str(e)}")
        
        return credentials

class LastPassImportHandler(ImportHandler):
    """Handler pour l'import de fichiers CSV de LastPass"""
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse un fichier CSV LastPass"""
        credentials = []
        try:
            # Décodage du contenu
            content = self.file_content.decode('utf-8-sig')
            csv_reader = csv.DictReader(io.StringIO(content))
            
            fieldnames = csv_reader.fieldnames
            if not fieldnames:
                raise ValueError("Le fichier CSV n'a pas d'en-têtes de colonnes")
            
            # Identifier les champs
            fields_map = {
                'name': next((f for f in fieldnames if f.lower() in ['name', 'title']), None),
                'url': next((f for f in fieldnames if f.lower() in ['url', 'web site']), None),
                'username': next((f for f in fieldnames if f.lower() in ['username', 'login', 'user name']), None),
                'password': next((f for f in fieldnames if f.lower() in ['password', 'pass']), None),
                'notes': next((f for f in fieldnames if f.lower() in ['extra', 'notes', 'note']), None),
                'group': next((f for f in fieldnames if f.lower() in ['grouping', 'group', 'folder']), None)
            }
            
            for row in csv_reader:
                cred = {
                    'name': row.get(fields_map['name'], ''),
                    'website': row.get(fields_map['url'], ''),
                    'username': row.get(fields_map['username'], ''),
                    'password': row.get(fields_map['password'], ''),
                    'notes': row.get(fields_map['notes'], ''),
                    'tags': []
                }
                
                # Utiliser le groupe comme tag
                if fields_map['group'] and row.get(fields_map['group']):
                    cred['tags'] = [row[fields_map['group']]]
                
                # Si username contient @, c'est probablement un email
                if '@' in cred['username']:
                    cred['email'] = cred['username']
                
                # Ne prendre que les credentials qui ont au moins un nom
                if cred['name']:
                    credentials.append(cred)
        
        except Exception as e:
            raise ValueError(f"Erreur lors du parsing du fichier LastPass: {str(e)}")
        
        return credentials


# Créer les handlers pour les autres formats: Dashlane, 1Password, etc.
class DashlaneImportHandler(ImportHandler):
    """Handler pour l'import de fichiers CSV de Dashlane"""
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse un fichier CSV Dashlane"""
        credentials = []
        try:
            # Vérifier si un mot de passe est fourni (requis pour Dashlane)
            if not self.password:
                raise ValueError("Un mot de passe est requis pour les exports Dashlane")
            
            # Décodage du contenu
            content = self.file_content.decode('utf-8-sig')
            csv_reader = csv.DictReader(io.StringIO(content))
            
            fieldnames = csv_reader.fieldnames
            if not fieldnames:
                raise ValueError("Le fichier CSV n'a pas d'en-têtes de colonnes")
            
            # Identifier les champs spécifiques à Dashlane
            fields_map = {
                'name': next((f for f in fieldnames if f.lower() in ['title', 'name']), None),
                'url': next((f for f in fieldnames if f.lower() in ['url', 'website']), None),
                'username': next((f for f in fieldnames if f.lower() in ['login', 'username', 'email']), None),
                'password': next((f for f in fieldnames if f.lower() in ['password']), None),
                'notes': next((f for f in fieldnames if f.lower() in ['notes', 'note', 'comments']), None),
                'category': next((f for f in fieldnames if f.lower() in ['category', 'group']), None)
            }
            
            for row in csv_reader:
                cred = {
                    'name': row.get(fields_map['name'], ''),
                    'website': row.get(fields_map['url'], ''),
                    'username': row.get(fields_map['username'], ''),
                    'password': row.get(fields_map['password'], ''),
                    'notes': row.get(fields_map['notes'], ''),
                    'tags': []
                }
                
                # Utiliser la catégorie comme tag
                if fields_map['category'] and row.get(fields_map['category']):
                    cred['tags'] = [row[fields_map['category']]]
                
                # Si username contient @, c'est probablement un email
                if '@' in cred['username']:
                    cred['email'] = cred['username']
                
                # Ne prendre que les credentials qui ont au moins un nom
                if cred['name']:
                    credentials.append(cred)
        
        except Exception as e:
            raise ValueError(f"Erreur lors du parsing du fichier Dashlane: {str(e)}")
        
        return credentials


class OnePasswordImportHandler(ImportHandler):
    """Handler pour l'import de fichiers CSV de 1Password"""
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse un fichier CSV 1Password"""
        credentials = []
        try:
            # Vérifier si un mot de passe est fourni (requis pour 1Password)
            if not self.password:
                raise ValueError("Un mot de passe est requis pour les exports 1Password")
            
            # Décodage du contenu
            content = self.file_content.decode('utf-8-sig')
            csv_reader = csv.DictReader(io.StringIO(content))
            
            fieldnames = csv_reader.fieldnames
            if not fieldnames:
                raise ValueError("Le fichier CSV n'a pas d'en-têtes de colonnes")
            
            # Identifier les champs spécifiques à 1Password
            fields_map = {
                'name': next((f for f in fieldnames if f.lower() in ['title', 'name']), None),
                'url': next((f for f in fieldnames if f.lower() in ['url', 'website']), None),
                'username': next((f for f in fieldnames if f.lower() in ['username', 'login_username']), None),
                'password': next((f for f in fieldnames if f.lower() in ['password', 'login_password']), None),
                'notes': next((f for f in fieldnames if f.lower() in ['notes', 'notesplain']), None),
                'category': next((f for f in fieldnames if f.lower() in ['category', 'type']), None)
            }
            
            for row in csv_reader:
                # Ne traiter que les entrées de type "Login"
                if fields_map['category'] and row.get(fields_map['category']) and 'login' not in row[fields_map['category']].lower():
                    continue
                
                cred = {
                    'name': row.get(fields_map['name'], ''),
                    'website': row.get(fields_map['url'], ''),
                    'username': row.get(fields_map['username'], ''),
                    'password': row.get(fields_map['password'], ''),
                    'notes': row.get(fields_map['notes'], ''),
                    'tags': []
                }
                
                # Si username contient @, c'est probablement un email
                if '@' in cred['username']:
                    cred['email'] = cred['username']
                
                # Ne prendre que les credentials qui ont au moins un nom
                if cred['name']:
                    credentials.append(cred)
        
        except Exception as e:
            raise ValueError(f"Erreur lors du parsing du fichier 1Password: {str(e)}")
        
        return credentials


class KeeperImportHandler(ImportHandler):
    """Handler pour l'import de fichiers CSV de Keeper"""
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse un fichier CSV Keeper"""
        credentials = []
        try:
            # Vérifier si un mot de passe est fourni (requis pour Keeper)
            if not self.password:
                raise ValueError("Un mot de passe est requis pour les exports Keeper")
            
            # Décodage du contenu
            content = self.file_content.decode('utf-8-sig')
            csv_reader = csv.DictReader(io.StringIO(content))
            
            fieldnames = csv_reader.fieldnames
            if not fieldnames:
                raise ValueError("Le fichier CSV n'a pas d'en-têtes de colonnes")
            
            # Identifier les champs spécifiques à Keeper
            fields_map = {
                'name': next((f for f in fieldnames if f.lower() in ['title', 'record name']), None),
                'url': next((f for f in fieldnames if f.lower() in ['login url', 'url', 'website']), None),
                'username': next((f for f in fieldnames if f.lower() in ['login', 'username']), None),
                'password': next((f for f in fieldnames if f.lower() in ['password', 'password value']), None),
                'notes': next((f for f in fieldnames if f.lower() in ['notes', 'note']), None),
                'folder': next((f for f in fieldnames if f.lower() in ['folder', 'group']), None)
            }
            
            for row in csv_reader:
                cred = {
                    'name': row.get(fields_map['name'], ''),
                    'website': row.get(fields_map['url'], ''),
                    'username': row.get(fields_map['username'], ''),
                    'password': row.get(fields_map['password'], ''),
                    'notes': row.get(fields_map['notes'], ''),
                    'tags': []
                }
                
                # Utiliser le dossier comme tag
                if fields_map['folder'] and row.get(fields_map['folder']):
                    cred['tags'] = [row[fields_map['folder']]]
                
                # Si username contient @, c'est probablement un email
                if '@' in cred['username']:
                    cred['email'] = cred['username']
                
                # Ne prendre que les credentials qui ont au moins un nom
                if cred['name']:
                    credentials.append(cred)
        
        except Exception as e:
            raise ValueError(f"Erreur lors du parsing du fichier Keeper: {str(e)}")
        
        return credentials


# Factory pour créer le bon handler selon la source d'import
def get_import_handler(source: str, user: User, file_content: bytes, password: str = None) -> ImportHandler:
    """
    Factory pour créer le bon handler d'import selon la source.
    """
    handlers = {
        'csv': CSVImportHandler,
        'google': GooglePasswordManagerImportHandler,
        'bitwarden': BitwardenImportHandler,
        'lastpass': LastPassImportHandler,
        'dashlane': DashlaneImportHandler,
        'onepassword': OnePasswordImportHandler,
        'keeper': KeeperImportHandler
    }
    
    if source not in handlers:
        raise ValueError(f"Source d'import non prise en charge: {source}")
    
    return handlers[source](user, file_content, password)