# security/views.py
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q, F
from django.utils import timezone
from django.shortcuts import get_object_or_404

from credentials.models import Credential, CredentialShare
from .models import SecurityAudit, CredentialStrengthCache, AuditLogEntry
from .serializers import (
    SecurityAuditSerializer,
    CredentialWithStrengthSerializer,
    SecurityDashboardSerializer,
    AuditLogEntrySerializer
)
from .password_utils import audit_user_security

class SecurityViewSet(viewsets.ViewSet):
    """
    API pour la gestion de la sécurité des credentials
    """
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['GET'])
    def dashboard(self, request):
        """
        Récupère les données pour le tableau de bord de sécurité
        GET /api/security/dashboard/
        """
        user = request.user
    
        # Récupérer les credentials
        credentials = Credential.objects.filter(user=user)
        credentials_count = credentials.count()
    
        # Récupérer les partages
        shares = CredentialShare.objects.filter(creator=user)
        active_shares = shares.filter(
            Q(expires_at__gt=timezone.now()) & 
            (Q(max_access_count__isnull=True) | Q(access_count__lt=F('max_access_count')))
        ).count()
        total_shares = shares.count()
    
        # Récupérer le dernier audit
        try:
            last_audit = SecurityAudit.objects.filter(user=user).latest('created_at')
            security_score = last_audit.security_score
            weak_passwords = last_audit.audit_details.get('weak_passwords', [])
            duplicate_passwords = last_audit.audit_details.get('duplicate_passwords', [])
            old_passwords = last_audit.audit_details.get('old_passwords', [])
            last_audit_date = last_audit.created_at
        except SecurityAudit.DoesNotExist:
            # Aucun audit disponible
            security_score = 0
            weak_passwords = []
            duplicate_passwords = []
            old_passwords = []
            last_audit_date = None
    
        # Récupérer les 5 credentials les plus récents
        # Utiliser 'id' au lieu de 'created_at' pour le tri
        recent_creds = list(credentials.order_by('-id')[:5])
    
        # S'assurer que tous les credentials récents ont une évaluation de force
        for cred in recent_creds:
            if not hasattr(cred, 'strength_cache'):
                # Force une évaluation de base pour l'affichage
                CredentialStrengthCache.objects.get_or_create(
                    credential=cred,
                    defaults={'strength': 'medium', 'score': 50}
                )
    
        # Utiliser CredentialWithStrengthSerializer pour inclure les informations de force
        from .serializers import CredentialWithStrengthSerializer
        recent_credentials_serializer = CredentialWithStrengthSerializer(recent_creds, many=True)
        recent_credentials = recent_credentials_serializer.data
    
        # Préparer les données de réponse
        dashboard_data = {
            'security_score': security_score,
            'credentials_count': credentials_count,
            'active_shares_count': active_shares,
            'total_shares_count': total_shares,
            'weak_passwords': weak_passwords,
            'duplicate_passwords': duplicate_passwords,
            'old_passwords': old_passwords,
            'recent_credentials': recent_credentials,
            'last_audit': last_audit_date
        }
    
        return Response(dashboard_data)
    
    @action(detail=False, methods=['GET'])
    def silent_audit(self, request):
        """
        Lance un audit de sécurité complet sans créer d'entrée de journal
        GET /api/security/silent_audit/
        """
        user = request.user
    
        # Exécuter l'audit (sans créer d'entrée de journal)
        audit_results = audit_user_security(user)
    
        return Response({
            'security_score': audit_results['security_score'],
            'weak_passwords_count': len(audit_results['weak_passwords']),
            'duplicate_passwords_count': len(audit_results['duplicate_passwords']),
            'old_passwords_count': len(audit_results['old_passwords']),
            'total_credentials': audit_results['total_credentials']
        })
    
    @action(detail=False, methods=['POST'])
    def run_audit(self, request):
        """
        Lance un audit de sécurité complet
        POST /api/security/run_audit/
        """
        user = request.user
        
        # Exécuter l'audit
        audit_results = audit_user_security(user)
        
        # Enregistrer l'action dans le journal d'activité
        AuditLogEntry.objects.create(
            user=user,
            action_type='security_audit',
            action_detail=f"Audit de sécurité - Score: {audit_results['security_score']}",
            ip_address=self._get_client_ip(request)
        )
        
        return Response({
            'security_score': audit_results['security_score'],
            'weak_passwords_count': len(audit_results['weak_passwords']),
            'duplicate_passwords_count': len(audit_results['duplicate_passwords']),
            'old_passwords_count': len(audit_results['old_passwords']),
            'total_credentials': audit_results['total_credentials']
        })
    
    @action(detail=False, methods=['GET'])
    def audit_history(self, request):
        """
        Récupère l'historique des audits de sécurité
        GET /api/security/audit_history/
        """
        audits = SecurityAudit.objects.filter(user=request.user)
        serializer = SecurityAuditSerializer(audits, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['GET'])
    def password_health(self, request):
        """
        Récupère l'état de santé des mots de passe
        GET /api/security/password_health/
        """
        credentials = Credential.objects.filter(user=request.user)
        
        # S'assurer que tous les credentials ont une évaluation de force
        for cred in credentials:
            if not hasattr(cred, 'strength_cache'):
                # Créer une entrée par défaut
                CredentialStrengthCache.objects.create(
                    credential=cred,
                    strength='medium',
                    score=50
                )
        
        serializer = CredentialWithStrengthSerializer(credentials, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['GET'])
    def audit_log(self, request):
        """
        Récupère le journal d'activité de l'utilisateur
        GET /api/security/audit_log/
        """
        logs = AuditLogEntry.objects.filter(user=request.user).order_by('-created_at')[:50]
        serializer = AuditLogEntrySerializer(logs, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['GET'])
    def credential_strength(self, request, pk=None):
        """
        Récupère la force d'un mot de passe spécifique
        GET /api/security/credential_strength/<id>/
        """
        credential = get_object_or_404(Credential, id=pk, user=request.user)
        
        try:
            strength_cache = CredentialStrengthCache.objects.get(credential=credential)
        except CredentialStrengthCache.DoesNotExist:
            # Force une nouvelle évaluation
            from .password_utils import evaluate_password_strength
            from credentials.crypto_utils import decrypt_password
            
            try:
                plaintext = decrypt_password(credential.password_encrypted)
                strength, score = evaluate_password_strength(plaintext)
                
                strength_cache = CredentialStrengthCache.objects.create(
                    credential=credential,
                    strength=strength,
                    score=score
                )
            except Exception as e:
                return Response({
                    'error': f"Impossible d'évaluer la force du mot de passe: {str(e)}"
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
            'credential_id': credential.id,
            'credential_name': credential.name,
            'strength': strength_cache.strength,
            'score': strength_cache.score
        })
    
    def _get_client_ip(self, request):
        """Récupère l'adresse IP du client"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip