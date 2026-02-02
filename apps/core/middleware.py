import logging
from django.contrib.auth.models import AnonymousUser
from apps.users.authentication import CustomAuthentication

logger = logging.getLogger(__name__)


class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            user = self._authenticate_token(token)

            if user:
                request.user = user
                logger.debug(f"User authenticated via JWT: {user.email}")
            else:
                request.user = AnonymousUser()
                logger.debug("JWT authentication failed, user set to AnonymousUser")
        else:
            request.user = AnonymousUser()

        response = self.get_response(request)
        return response

    def _authenticate_token(self, token):
        try:
            user = CustomAuthentication.get_user_from_token(token)
            return user
        except Exception as e:
            logger.warning(f"Token authentication failed: {str(e)}")
            return None


class RequestLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.conf import settings

        if settings.DEBUG:
            user_info = f"User: {request.user}" if hasattr(request, 'user') else "Anonymous"
            logger.info(f"[REQUEST] {request.method} {request.path} | {user_info}")

        response = self.get_response(request)

        if settings.DEBUG:
            logger.info(f"[RESPONSE] {request.method} {request.path} | Status: {response.status_code}")

        return response