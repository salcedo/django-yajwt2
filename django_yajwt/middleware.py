from django_yajwt.auth import JWTAuthentication

from jwt import PyJWTError


try:
    from rest_framework.exceptions import AuthenticationFailed
except ImportError:
    AuthenticationFailed = None


class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_auth = JWTAuthentication()

    def __call__(self, request):
        if request.user.is_authenticated:
            return self.get_response(request)

        user = self._validate_authorization_token(request)
        if user is not None:
            request.user = user

        return self.get_response(request)

    def authenticate(self, request):
        if request.user.is_authenticated:
            return (request.user, None)

        user = self._validate_authorization_token(request)
        if user is None:
            if AuthenticationFailed is not None:
                raise AuthenticationFailed(_('Authentication failed'))
            else:
                raise

        return (user, None)

    def authenticate_header(self, request):
        return self.jwt_auth.token_prefix

    def _validate_authorization_token(self, request):
        user = None
        try:
            authorization = request.headers.get('Authorization', None)
            if authorization is None:
                return None
            if not authorization.startswith(self.jwt_auth.token_prefix):
                return None

            token = authorization.split(self.jwt_auth.token_prefix)[1]
            payload = self.jwt_auth.decode_jwt(token)
            user = self.jwt_auth.get_user(payload['sub'])
        except (IndexError, KeyError, PyJWTError):
            return None

        return user
