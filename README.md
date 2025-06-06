# FireKey Backend 🔐

[![Django](https://img.shields.io/badge/Django-5.1.7-092E20?style=for-the-badge&logo=django&logoColor=white)](https://djangoproject.com/)
[![Django REST Framework](https://img.shields.io/badge/DRF-3.14.0-ff1709?style=for-the-badge&logo=django&logoColor=white)](https://www.django-rest-framework.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-316192?style=for-the-badge&logo=postgresql&logoColor=white)](https://postgresql.org/)
[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org/)

**FireKey Backend** est une API REST haute performance construite avec Django, conçue pour gérer de manière sécurisée les mots de passe et données sensibles. Cette solution backend implémente un chiffrement de niveau militaire, une authentification multi-facteurs, et un système d'audit complet pour garantir la sécurité maximale des données utilisateurs.

## ✨ Fonctionnalités Principales

### 🔒 Sécurité de Niveau Entreprise
- **Chiffrement AES-256-CBC** : Protection cryptographique des mots de passe
- **Authentification JWT** : Tokens sécurisés avec rotation automatique
- **2FA TOTP** : Authentification à deux facteurs compatible Google Authenticator
- **Hachage Adaptatif** : Support Argon2/bcrypt/scrypt avec configuration personnalisée
- **Audit Trail** : Journalisation complète des activités sensibles

### 🛡️ Protection Avancée des Données
- **Clés de Chiffrement Uniques** : Dérivation PBKDF2 par utilisateur
- **Vecteurs d'Initialisation Aléatoires** : Protection contre les attaques par pattern
- **Credentials Sensibles** : Couche de protection supplémentaire
- **Middleware de Sécurité** : Protection CSRF, CORS, et rate limiting
- **Validation Cryptographique** : Vérification d'intégrité des données

### 📊 Intelligence et Analyse
- **Audit de Sécurité Automatique** : Évaluation proactive des risques
- **Détection des Vulnérabilités** : Identification des mots de passe faibles/dupliqués
- **Dashboard de Sécurité** : Métriques et indicateurs en temps réel
- **Scoring Intelligent** : Algorithme d'évaluation de la force des mots de passe
- **Alertes Proactives** : Notifications automatiques des risques

### 🔄 Intégration et Portabilité
- **Import/Export Universel** : Support multi-format (15+ gestionnaires)
- **Partage Sécurisé** : Liens temporaires avec contrôles granulaires
- **API RESTful** : Interface standardisée et documentée
- **Système de Tags** : Organisation flexible et recherche avancée
- **Notifications Push** : Système de messagerie en temps réel

## 🚀 Stack Technologique

### Backend Core
- **Django 5.1.7** - Framework web Python robuste
- **Django REST Framework** - Toolkit API REST complet
- **PostgreSQL 15+** - Base de données relationnelle haute performance
- **Celery** - Traitement de tâches asynchrones

### Sécurité & Cryptographie
- **PyJWT** - Gestion des tokens JSON Web Token
- **Cryptography** - Bibliothèque cryptographique moderne
- **Argon2** - Algorithme de hachage résistant aux GPU
- **PyOTP** - Implémentation TOTP/HOTP pour 2FA

### Intégration & Utilities
- **Pandas** - Traitement de données pour import/export
- **python-decouple** - Gestion sécurisée de la configuration
- **Django-CORS-Headers** - Gestion des politiques CORS
- **psycopg2** - Adaptateur PostgreSQL optimisé

## 📦 Installation et Configuration

### Prérequis Système
- Python 3.8+ avec pip
- PostgreSQL 15+ configuré et démarré
- Redis (optionnel, pour Celery)
- Git pour le versioning

### Installation Rapide
```bash
# Cloner le repository
git clone https://github.com/imDenq/firekey-backend.git
cd firekey-backend

# Créer l'environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/macOS
# ou venv\Scripts\activate # Windows

# Installer les dépendances
pip install -r requirements.txt

# Configuration de base
cp .env.example .env
# Éditer .env avec vos paramètres
```

### Configuration Base de Données
```bash
# Créer la base de données PostgreSQL
createdb firekey_db -U postgres

# Appliquer les migrations
python manage.py makemigrations
python manage.py migrate

# Créer un superutilisateur
python manage.py createsuperuser
```

### Variables d'Environnement
```env
# Configuration Django
DEBUG=False
SECRET_KEY=your-super-secret-django-key-here
ALLOWED_HOSTS=localhost,127.0.0.1,yourdomain.com

# Base de données
DATABASE_URL=postgresql://username:password@localhost:5432/firekey_db

# Sécurité
AES_SECRET_KEY=your-32-byte-base64-encoded-aes-key
JWT_SECRET_KEY=your-jwt-signing-key
PASSWORD_RESET_TIMEOUT=3600

# Email (optionnel)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Redis (pour Celery)
REDIS_URL=redis://localhost:6379/0
```

### Génération des Clés de Sécurité
```bash
# Générer une clé AES sécurisée
python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"

# Générer une clé secrète Django
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

## 🛠️ Commandes de Développement

```bash
# Démarrage du serveur de développement
python manage.py runserver

# Tests complets
python manage.py test

# Tests avec couverture
coverage run --source='.' manage.py test
coverage report -m

# Collecte des fichiers statiques
python manage.py collectstatic

# Shell Django interactif
python manage.py shell

# Créer une nouvelle migration
python manage.py makemigrations app_name

# Vérification de la configuration
python manage.py check --deploy
```

## 🏗️ Architecture API

### Structure du Projet
```
firekey-backend/
├── accounts/              # Authentification et gestion utilisateurs
│   ├── models.py         # Modèles User, Profile, AuthLog
│   ├── views.py          # Endpoints auth et profil
│   ├── serializers.py    # Sérialisation des données
│   └── permissions.py    # Contrôles d'accès personnalisés
├── credentials/          # Gestion des mots de passe
│   ├── models.py         # Credential, Tag, Share
│   ├── encryption.py     # Moteur de chiffrement
│   ├── views.py          # CRUD et partage
│   └── validators.py     # Validation des données
├── security/             # Audit et analyse sécurité
│   ├── models.py         # AuditLog, SecurityMetrics
│   ├── analyzers.py      # Algorithmes d'analyse
│   ├── tasks.py          # Tâches asynchrones
│   └── views.py          # Dashboard et rapports
├── notifications/        # Système de notifications
├── importexport/         # Import/export multi-format
│   ├── parsers/          # Parseurs par gestionnaire
│   ├── processors.py     # Logique de traitement
│   └── exporters.py      # Générateurs d'export
└── myproject/            # Configuration Django
    ├── settings/         # Configuration par environnement
    ├── urls.py           # Routage principal
    └── wsgi.py           # Point d'entrée WSGI
```

### Endpoints API Principaux

#### 🔐 Authentification & Sécurité
```http
POST   /auth/register/              # Inscription utilisateur
POST   /auth/login/                 # Connexion standard
POST   /auth/two-factor-auth/       # Connexion avec 2FA
POST   /auth/token/refresh/         # Renouvellement token
GET    /auth/protected/             # Vérification de session
POST   /auth/logout/                # Déconnexion sécurisée
```

#### 🗝️ Gestion des Credentials
```http
GET    /api/credentials/            # Liste des credentials
POST   /api/credentials/            # Créer un credential
GET    /api/credentials/{id}/       # Détails d'un credential
PATCH  /api/credentials/{id}/       # Modifier un credential
DELETE /api/credentials/{id}/       # Supprimer un credential
GET    /api/credentials/{id}/decrypt/ # Déchiffrer mot de passe
POST   /api/credentials/{id}/verify/ # Vérifier mot de passe maître
```

#### 🏷️ Système de Tags
```http
GET    /api/tags/                   # Liste des tags
POST   /api/tags/                   # Créer un tag
DELETE /api/tags/{id}/              # Supprimer un tag
POST   /api/credentials/{id}/add_tag/ # Ajouter tag à credential
```

#### 🔗 Partage Sécurisé
```http
GET    /api/shares/                 # Mes partages
POST   /api/shares/                 # Créer un partage
PATCH  /api/shares/{id}/            # Modifier un partage
DELETE /api/shares/{id}/            # Supprimer un partage
GET    /api/share/{id}/{key}/       # Accès public au partage
```

#### 📊 Sécurité & Audit
```http
GET    /api/security/dashboard/     # Métriques de sécurité
POST   /api/security/run_audit/     # Lancer audit de sécurité
GET    /api/security/audit_log/     # Journal d'audit
GET    /api/security/silent_audit/  # Audit sans journalisation
```

#### 📤 Import/Export
```http
GET    /api/import-export/options/  # Formats supportés
POST   /api/import-export/upload/   # Upload fichier d'import
GET    /api/import-export/preview/{id}/ # Prévisualiser import
POST   /api/import-export/import/   # Exécuter import
POST   /api/import-export/export/   # Générer export
```

## 🔒 Sécurité et Conformité

### Chiffrement et Protection des Données
- **AES-256-CBC** avec clés dérivées PBKDF2 (100,000 itérations)
- **Vecteurs d'initialisation** générés cryptographiquement
- **Séparation des clés** : Une clé unique par utilisateur
- **Chiffrement au repos** : Base de données chiffrée
- **Chiffrement en transit** : HTTPS/TLS 1.3 obligatoire

### Authentification Multi-Couches
- **JWT avec expiration** : Tokens courts + refresh tokens longs
- **2FA TOTP** : Compatible RFC 6238 (Google Authenticator, Authy)
- **Rate Limiting** : Protection contre brute force
- **Session Management** : Invalidation sécurisée des tokens
- **Device Tracking** : Détection d'accès suspects

### Audit et Conformité
- **Journalisation complète** : Toutes actions sensibles tracées
- **Retention Policy** : Conservation configurable des logs
- **Anonymisation** : Protection des données personnelles
- **GDPR Ready** : Respect du règlement européen
- **SOC 2 Type II** : Contrôles de sécurité enterprise

### Tests de Sécurité
```bash
# Audit de sécurité des dépendances
pip-audit

# Test de pénétration automatisé
python manage.py test security.tests.PenetrationTests

# Vérification des configurations
python manage.py check --deploy --fail-level=WARNING

# Scan des vulnérabilités statiques
bandit -r . -x tests/
```

## 🚀 Déploiement et Production

### Configuration Docker
```dockerfile
# Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["gunicorn", "myproject.wsgi:application", "--bind", "0.0.0.0:8000"]
```

### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/firekey
    depends_on:
      - db
      - redis
  
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: firekey
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  redis:
    image: redis:7-alpine
    
volumes:
  postgres_data:
```

### Déploiement Production
```bash
# Variables d'environnement production
export DEBUG=False
export ALLOWED_HOSTS=api.firekey.com
export DATABASE_URL=postgresql://user:pass@prod-db:5432/firekey

# Serveur WSGI avec Gunicorn
gunicorn myproject.wsgi:application \
  --bind 0.0.0.0:8000 \
  --workers 4 \
  --worker-class gevent \
  --worker-connections 1000 \
  --max-requests 1000 \
  --max-requests-jitter 50 \
  --timeout 30 \
  --keep-alive 2
```

### Monitoring et Métriques
- **Health Check** : `/health/` endpoint pour monitoring
- **Metrics** : Prometheus/Grafana compatible
- **Logging** : Structured logging avec ELK Stack
- **APM** : Application Performance Monitoring
- **Alerting** : Notifications automatiques des incidents

## 🧪 Tests et Qualité

### Suite de Tests Complète
```bash
# Tests unitaires
python manage.py test accounts credentials security

# Tests d'intégration
python manage.py test --tag=integration

# Tests de performance
python manage.py test --tag=performance

# Tests de sécurité
python manage.py test security.tests.SecurityTests
```

### Métriques de Qualité
- **Couverture de code** : >90% target
- **Complexité cyclomatique** : Maintenue <10
- **Documentation** : Docstrings complètes
- **Type Hints** : Types statiques avec mypy
- **Code Style** : Black + isort + flake8

### CI/CD Pipeline
```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install coverage
      - name: Run tests
        run: |
          coverage run --source='.' manage.py test
          coverage report --fail-under=90
      - name: Security audit
        run: pip-audit
```

## 📈 Performance et Scalabilité

### Optimisations Base de Données
- **Index stratégiques** : Optimisation des requêtes fréquentes
- **Connection Pooling** : Réutilisation des connexions DB
- **Query Optimization** : Requêtes SQL optimisées
- **Caching Strategy** : Redis pour mise en cache
- **Pagination** : Limitation des résultats API

### Scaling Horizontal
- **Stateless Design** : Support multi-instances
- **Load Balancing** : Distribution de charge
- **Database Replication** : Master/Slave PostgreSQL
- **CDN Integration** : Fichiers statiques optimisés
- **Microservices Ready** : Architecture modulaire

## 🤝 Contribution et Développement

### Guide de Contribution
1. **Fork** le repository
2. Créer une **branche feature** : `git checkout -b feature/awesome-feature`
3. **Développer** avec les tests associés
4. **Valider** : `python manage.py test`
5. **Commit** : `git commit -m 'feat: add awesome feature'`
6. **Push** : `git push origin feature/awesome-feature`  
7. Créer une **Pull Request**

### Standards de Développement
- **PEP 8** : Style guide Python officiel
- **Django Best Practices** : Conventions du framework
- **Conventional Commits** : Messages structurés
- **TDD/BDD** : Tests en premier
- **Code Reviews** : Validation par les pairs

### Environnement de Développement
```bash
# Installation des outils de développement
pip install -r requirements-dev.txt

# Pre-commit hooks
pre-commit install

# Formatage automatique
black .
isort .

# Linting
flake8 .
mypy .
```

## 📊 Roadmap et Statut

### ✅ Fonctionnalités Complétées
- Authentification JWT + 2FA
- Chiffrement AES-256 des credentials
- API REST complète avec DRF
- Système d'audit et de sécurité
- Import/export multi-format
- Partage sécurisé temporaire
- Dashboard de sécurité

### 🚧 En Développement
- [ ] Tests unitaires complets (90%+ couverture)
- [ ] Documentation API complète (OpenAPI/Swagger)
- [ ] Pipeline CI/CD complet
- [ ] Monitoring et métriques avancées
- [ ] Performance benchmarking

### 🔮 Roadmap Future
- [ ] Intégration Kubernetes
- [ ] Support multi-tenant
- [ ] API GraphQL
- [ ] Machine Learning pour détection d'anomalies
- [ ] Intégrations Enterprise (LDAP/SAML)

## 📞 Support et Contact

### Équipe de Développement
- **Lead Developer** : Theo Kaszak
- **Email** : contact@theokaszak.fr
- **Frontend Repository** : [FireKey Frontend](https://github.com/imDenq/firekey-frontend)

### Obtenir de l'Aide
- 📚 **Documentation** : [API Documentation](../../wiki)
- 🐛 **Bug Reports** : [GitHub Issues](../../issues)
- 💡 **Feature Requests** : [GitHub Discussions](../../discussions)
- 🔒 **Contact** : contact@theokaszak.fr

### Statut du Projet
🚀 **Version Beta** - Prêt pour les tests utilisateurs

---

<div align="center">

**[⭐ Star this project](../../stargazers)** • **[🍴 Fork](../../fork)** • **[📋 Report Issues](../../issues)**

Fait avec ❤️ par denq :)

</div>