from django_yajwt.auth import JWTAuthentication

from jwt import PyJWTError


jwt_auth = JWTAuthentication()


try:
    from rest_framework.authentication import BaseAuthentication
    from rest_framework.exceptions import AuthenticationFailed

    class JWTAuthenticationDRF(BaseAuthentication):
        def authenticate(self, request):
            user = validate_authorization_token(request)
            if user is None:
                raise AuthenticationFailed('Authentication failed')
            else:
                return (user, None)

        def authenticate_header(self, request):
            return jwt_auth.token_prefix
except ImportError:
    pass


class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            return self.get_response(request)

        user = validate_authorization_token(request)
        if user is not None:
            request.user = user

        return self.get_response(request)


def validate_authorization_token(request):
    user = None
    try:
        authorization = request.headers.get('Authorization', None)
        if authorization is None:
            return None
        if not authorization.startswith(jwt_auth.token_prefix):
            return None

        token = authorization.split(jwt_auth.token_prefix)[1]
        payload = jwt_auth.decode_jwt(token)
        user = jwt_auth.get_user(payload['sub'])
    except (IndexError, KeyError, PyJWTError):
        return None

    return user
