from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError
from django.contrib.auth import logout
from .models import User
from .serializers import (
    RegisterSerializer,
    VerifyOtpSerializer,
    LoginSerializer,
    UpdateProfileSerializer,
    SoftDeleteSerializer,
    ProfileSerializer
)
from .permissions import IsAuthenticatedAndVerified
import logging

logger = logging.getLogger(__name__)


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            logger.warning(f"Registration validation failed: {e.detail}")
            return Response({
                "error": "Ошибка валидации данных",
                "details": e.detail
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = serializer.save()
            logger.info(f"New user registered successfully: {user.email}")
        except Exception as e:
            logger.error(f"User registration failed: {str(e)}")
            return Response({
                "error": "Не удалось создать пользователя",
                "details": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "message": "Пользователь успешно зарегистрирован. Проверьте email для подтверждения.",
            "user": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_verified": user.is_verified
            }
        }, status=status.HTTP_201_CREATED)


class VerifyOtpView(generics.GenericAPIView):
    serializer_class = VerifyOtpSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            logger.warning(f"OTP verification failed: {e.detail}")
            return Response({
                "error": "Ошибка подтверждения OTP",
                "details": e.detail
            }, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']

        return Response({
            "message": "Email успешно подтверждён. Теперь вы можете войти в систему.",
            "user": {
                "id": user.id,
                "email": user.email,
                "is_verified": user.is_verified
            }
        }, status=status.HTTP_200_OK)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            logger.warning(f"Login failed: {e.detail}")
            return Response({
                "error": "Ошибка входа",
                "details": e.detail
            }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "message": "Успешный вход в систему",
            "token": serializer.validated_data['token'],
            "user": {
                "id": serializer.validated_data['user'].id,
                "email": serializer.validated_data['user'].email,
                "first_name": serializer.validated_data['user'].first_name,
                "last_name": serializer.validated_data['user'].last_name
            }
        }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticatedAndVerified])
def logout_view(request):
    # FIX: проверяем, что пользователь аутентифицирован перед доступом к email
    if request.user.is_authenticated and hasattr(request.user, 'email'):
        logger.info(f"User logged out: {request.user.email}")
    else:
        logger.info("Anonymous user attempted logout")

    logout(request)

    return Response({
        "message": "Успешный выход из системы"
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticatedAndVerified])
def profile_view(request):
    serializer = ProfileSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)


class UpdateProfileView(generics.UpdateAPIView):
    serializer_class = UpdateProfileSerializer
    permission_classes = [IsAuthenticatedAndVerified]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)

        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            logger.warning(f"Profile update validation failed: {e.detail}")
            return Response({
                "error": "Ошибка валидации данных",
                "details": e.detail
            }, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()

        logger.info(f"Profile updated for user: {user.email}")

        if 'email' in request.data and request.data['email'] != instance.email:
            return Response({
                "message": "Профиль обновлён. Требуется подтверждение нового email.",
                "user": ProfileSerializer(user).data
            }, status=status.HTTP_200_OK)

        return Response({
            "message": "Профиль успешно обновлён",
            "user": ProfileSerializer(user).data
        }, status=status.HTTP_200_OK)


class SoftDeleteView(generics.DestroyAPIView):
    serializer_class = SoftDeleteSerializer
    permission_classes = [IsAuthenticatedAndVerified]

    def get_object(self):
        return self.request.user

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)

        try:
            serializer.save()
            logger.info(f"Account soft deleted for user: {instance.email}")
        except Exception as e:
            logger.error(f"Soft delete failed: {str(e)}")
            return Response({
                "error": "Не удалось деактивировать аккаунт"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        logout(request)

        return Response({
            "message": "Аккаунт успешно деактивирован"
        }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticatedAndVerified])
def test_protected_view(request):
    return Response({
        "message": f"Добро пожаловать, {request.user.first_name}!",
        "user": {
            "id": request.user.id,
            "email": request.user.email,
            "roles": [ur.role.name for ur in request.user.roles.all()]
        }
    }, status=status.HTTP_200_OK)

