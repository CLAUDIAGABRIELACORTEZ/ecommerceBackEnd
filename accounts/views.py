from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status

from accounts.models import CustomUser, Role, Permission
from accounts.serializers import CustomUserSerializer, RoleSerializer, PermissionSerializer

# ========== CRUD DE ROLES ==========

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_roles(request):
    roles = Role.objects.all()
    serializer = RoleSerializer(roles, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_role(request):
    serializer = RoleSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_role(request, role_id):
    try:
        role = Role.objects.get(pk=role_id)
    except Role.DoesNotExist:
        return Response({'error': 'Rol no encontrado'}, status=404)

    serializer = RoleSerializer(role, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=400)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_role(request, role_id):
    try:
        role = Role.objects.get(pk=role_id)
        role.delete()
        return Response({'message': 'Rol eliminado correctamente'})
    except Role.DoesNotExist:
        return Response({'error': 'Rol no encontrado'}, status=404)

# ========== CRUD DE PERMISOS ==========

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_permissions(request):
    permissions = Permission.objects.all()
    serializer = PermissionSerializer(permissions, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_permission(request):
    serializer = PermissionSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_permission(request, permission_id):
    try:
        permission = Permission.objects.get(pk=permission_id)
    except Permission.DoesNotExist:
        return Response({'error': 'Permiso no encontrado'}, status=404)

    serializer = PermissionSerializer(permission, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=400)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_permission(request, permission_id):
    try:
        permission = Permission.objects.get(pk=permission_id)
        permission.delete()
        return Response({'message': 'Permiso eliminado correctamente'})
    except Permission.DoesNotExist:
        return Response({'error': 'Permiso no encontrado'}, status=404)

# ========== CRUD DE USUARIOS ==========

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_users(request):
    users = CustomUser.objects.all()
    serializer = CustomUserSerializer(users, many=True)
    return Response(serializer.data)

# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def get_user(request, user_id):
#     try:
#         user = CustomUser.objects.get(pk=user_id)
#     except CustomUser.DoesNotExist:
#         return Response({'error': 'Usuario no encontrado'}, status=404)
#     serializer = CustomUserSerializer(user)
#     return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_user(request):
    if not request.user.is_admin():
        return Response({'detail': 'No tenés permiso para crear usuarios'}, status=403)

    serializer = CustomUserSerializer(data=request.data, context={'request': request})

    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user(request, user_id):
    if not request.user.is_admin():
        return Response({'detail': 'No tenés permiso para editar usuarios'}, status=403)

    try:
        user = CustomUser.objects.get(pk=user_id)
    except CustomUser.DoesNotExist:
        return Response({'error': 'Usuario no encontrado'}, status=404)

    serializer = CustomUserSerializer(user, data=request.data, context={'request': request})
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=400)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_user(request, user_id):
    try:
        user = CustomUser.objects.get(pk=user_id)
        user.delete()
        return Response({'message': 'Usuario eliminado correctamente'})
    except CustomUser.DoesNotExist:
        return Response({'error': 'Usuario no encontrado'}, status=404)

# # ========== ASIGNACIÓN DE ROL ==========

# @api_view(['POST'])
# @permission_classes([IsAdminUser])
# def assign_role(request, user_id):
#     try:
#         user = CustomUser.objects.get(pk=user_id)
#         role = Role.objects.get(pk=request.data['role_id'])
#         user.role = role
#         user.save()
#         return Response({'message': f'Rol "{role.name}" asignado a {user.username}'})
#     except (CustomUser.DoesNotExist, Role.DoesNotExist):
#         return Response({'error': 'Usuario o Rol no válido'}, status=400)

# NOTA: Los permisos ahora están vinculados al rol. El usuario hereda los permisos automáticamente desde su rol.
