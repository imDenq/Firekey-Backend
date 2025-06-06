# security/api_views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import AuditLogEntry

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def log_audit_event(request):
    """
    Crée une entrée de journal d'audit depuis n'importe quel point de l'application
    POST /api/log_event/
    {
        "action_type": "login",
        "action_detail": "Connexion depuis Paris, France",
        "related_object_id": null  // optionnel
    }
    """
    action_type = request.data.get('action_type')
    action_detail = request.data.get('action_detail', '')
    related_object_id = request.data.get('related_object_id')
    
    # Vérifier que le type d'action est valide
    valid_actions = [choice[0] for choice in AuditLogEntry.ACTION_TYPES]
    if action_type not in valid_actions:
        return Response(
            {"error": f"Type d'action invalide. Valeurs possibles: {', '.join(valid_actions)}"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Récupérer l'IP et les informations sur l'appareil
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip_address = x_forwarded_for.split(',')[0]
    else:
        ip_address = request.META.get('REMOTE_ADDR')
    
    device_info = request.META.get('HTTP_USER_AGENT', '')
    
    # Créer l'entrée de journal
    AuditLogEntry.objects.create(
        user=request.user,
        action_type=action_type,
        action_detail=action_detail,
        ip_address=ip_address,
        device_info=device_info,
        related_object_id=related_object_id
    )
    
    return Response({"detail": "Événement enregistré avec succès"}, status=status.HTTP_201_CREATED)