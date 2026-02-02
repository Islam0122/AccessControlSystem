from rest_framework import serializers
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from .models import User
from .authentication import CustomAuthentication, OTPService
import logging

logger = logging.getLogger(__name__)


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        min_length=6,
        style={'input_type': 'password'},
        help_text="Минимум 6 символов"
    )
    password2 = serializers.CharField(
        write_only=True,
        min_length=6,
        style={'input_type': 'password'},
        label="Подтверждение пароля"
    )

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'password2']

    def validate_email(self, value):
        email = value.lower().strip()

        if User.objects.filter(email=email).exists():
            logger.warning(f"Registration attempt with existing email: {email}")
            raise serializers.ValidationError("Этот email уже зарегистрирован")

        return email

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password != password2:
            logger.warning("Password mismatch during registration")
            raise serializers.ValidationError({
                "password": "Пароли не совпадают"
            })

        if len(password) < 6:
            raise serializers.ValidationError({
                "password": "Пароль должен содержать минимум 6 символов"
            })

        if not any(char.isdigit() for char in password):
            raise serializers.ValidationError({
                "password": "Пароль должен содержать хотя бы одну цифру"
            })

        if not any(char.isalpha() for char in password):
            raise serializers.ValidationError({
                "password": "Пароль должен содержать хотя бы одну букву"
            })

        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        password = validated_data.pop('password')
        validated_data['email'] = validated_data['email'].lower().strip()
        user = User(**validated_data)
        user.set_password(password)
        otp_code = OTPService.generate_otp()
        user.otp_code = otp_code
        user.otp_expires_at = timezone.now() + timedelta(minutes=10)
        user.save()
        logger.info(f"New user registered: {user.email}")
        self._send_otp_email(user)

        return user

    def _send_otp_email(self, user):
        from django.core.mail import send_mail

        subject = "Подтверждение регистрации - OTP код"
        message = f"""
Здравствуйте, {user.first_name}!

Ваш код подтверждения email: {user.otp_code}

Код действителен в течение 10 минут.

Если вы не регистрировались на нашем сайте, проигнорируйте это письмо.

---
Access Control System
        """

        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[user.email],
                fail_silently=False,
            )
            logger.info(f"OTP email sent successfully to {user.email}")
        except Exception as e:
            logger.error(f"Failed to send OTP email to {user.email}: {str(e)}")


class VerifyOtpSerializer(serializers.Serializer):
    email = serializers.EmailField(
        help_text="Email адрес пользователя"
    )
    otp_code = serializers.CharField(
        max_length=6,
        min_length=6,
        help_text="6-значный OTP код"
    )

    def validate(self, attrs):
        email = attrs.get('email').lower().strip()
        otp_code = attrs.get('otp_code')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning(f"OTP verification attempt for non-existent user: {email}")
            raise serializers.ValidationError("Пользователь не найден")

        if user.is_verified:
            logger.info(f"OTP verification attempt for already verified user: {email}")
            raise serializers.ValidationError("Email уже подтверждён")

        if not OTPService.verify_otp(user, otp_code):
            raise serializers.ValidationError("Неверный или истёкший OTP код")

        user.is_verified = True
        user.otp_code = None
        user.otp_expires_at = None
        user.save(update_fields=['is_verified', 'otp_code', 'otp_expires_at'])

        logger.info(f"Email verified successfully for user: {email}")

        attrs['user'] = user
        return attrs


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(
        help_text="Email адрес для входа"
    )
    password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'},
        help_text="Пароль"
    )
    token = serializers.CharField(
        read_only=True,
        help_text="JWT токен для последующих запросов"
    )

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if not email or not password:
            logger.warning("Login attempt with missing email or password")
            raise serializers.ValidationError("Email и пароль обязательны")

        try:
            user = CustomAuthentication.authenticate_user(email, password)
        except ValueError as e:
            raise serializers.ValidationError(str(e))

        if not user:
            raise serializers.ValidationError("Неверный email или пароль")
        token = CustomAuthentication.generate_jwt_token(user)
        attrs['token'] = token
        attrs['user'] = user
        logger.info(f"User logged in successfully: {email}")
        return attrs


class UpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']

    def validate_email(self, value):
        user = self.context['request'].user
        email = value.lower().strip()

        if User.objects.exclude(id=user.id).filter(email=email).exists():
            logger.warning(f"Profile update attempt with existing email: {email}")
            raise serializers.ValidationError("Этот email уже используется")

        return email

    def update(self, instance, validated_data):
        email_changed = 'email' in validated_data and validated_data['email'] != instance.email
        instance = super().update(instance, validated_data)
        if email_changed:
            instance.is_verified = False
            otp_code = OTPService.generate_otp()
            instance.otp_code = otp_code
            instance.otp_expires_at = timezone.now() + timedelta(minutes=10)

            instance.save(update_fields=['is_verified', 'otp_code', 'otp_expires_at'])

            logger.info(f"Email changed for user {instance.id}, verification required")

        return instance


class SoftDeleteSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = []

    def save(self, **kwargs):
        user = self.instance
        user.is_active = False
        user.save(update_fields=['is_active'])

        logger.info(f"User account soft deleted: {user.email}")
        return user


class ProfileSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id',
            'email',
            'first_name',
            'last_name',
            'is_verified',
            'is_active',
            'date_joined',
            'last_login',
            'roles'
        ]
        read_only_fields = fields

    def get_roles(self, obj):
        return [ur.role.name for ur in obj.roles.all()]