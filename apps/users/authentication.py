import jwt
import logging
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from .models import User

logger = logging.getLogger(__name__)


class CustomAuthentication:
    @staticmethod
    def authenticate_user(email, password):
        if not email or not password:
            logger.warning("Authentication attempt with empty email or password")
            raise ValueError("Email и пароль обязательны")

        try:
            user = User.objects.get(email=email.lower().strip())
        except User.DoesNotExist:
            logger.warning(f"Authentication failed: User not found for email {email}")
            return None

        if not user.is_active:
            logger.warning(f"Authentication failed: Inactive user {email}")
            return None

        if not user.is_verified:
            logger.warning(f"Authentication failed: Unverified user {email}")
            return None

        if not user.check_password(password):
            logger.warning(f"Authentication failed: Invalid password for {email}")
            return None

        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        logger.info(f"User authenticated successfully: {email}")
        return user

    @staticmethod
    def generate_jwt_token(user, expires_in_hours=24):
        if not user:
            raise ValueError("Пользователь обязателен для генерации токена")

        now = datetime.utcnow()
        payload = {
            'user_id': user.id,
            'email': user.email,
            'iat': now,  # issued at
            'exp': now + timedelta(hours=expires_in_hours),  # expiration
            'type': 'access'
        }
        token = jwt.encode(
            payload,
            settings.SECRET_KEY,
            algorithm='HS256'
        )

        logger.info(f"JWT token generated for user {user.email}")
        return token

    @staticmethod
    def decode_jwt_token(token):
        if not token:
            raise jwt.InvalidTokenError("Токен не может быть пустым")

        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=['HS256']
            )

            logger.debug(f"JWT token decoded successfully for user_id {payload.get('user_id')}")
            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            raise
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {str(e)}")
            raise

    @staticmethod
    def get_user_from_token(token):
        try:
            payload = CustomAuthentication.decode_jwt_token(token)
            user_id = payload.get('user_id')

            if not user_id:
                logger.warning("JWT token does not contain user_id")
                return None

            user = User.objects.get(id=user_id, is_active=True)
            return user

        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return None
        except User.DoesNotExist:
            logger.warning(f"User not found for user_id from token")
            return None


class OTPService:
    @staticmethod
    def generate_otp(length=6):
        import random
        import string

        digits = string.digits
        otp = ''.join(random.choice(digits) for _ in range(length))

        logger.debug(f"OTP code generated: {otp}")
        return otp

    @staticmethod
    def verify_otp(user, otp_code):
        if not user.otp_code or not otp_code:
            logger.warning(f"OTP verification failed: Missing OTP code for {user.email}")
            return False
        if user.otp_code != otp_code:
            logger.warning(f"OTP verification failed: Invalid code for {user.email}")
            return False
        if OTPService.is_otp_expired(user):
            logger.warning(f"OTP verification failed: Expired code for {user.email}")
            return False

        logger.info(f"OTP verified successfully for {user.email}")
        return True

    @staticmethod
    def is_otp_expired(user):
        if not user.otp_expires_at:
            return True

        return timezone.now() > user.otp_expires_at