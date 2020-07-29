import logging

from django.contrib.auth.models import AnonymousUser

from django_yajwt.auth import JWTAuthentication

from jwt import PyJWTError


logger = logging.getLogger(__name__)


class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_auth = JWTAuthentication()

    def __call__(self, request):
        if isinstance(request.user, self.jwt_auth.UserModel):
            return self.get_response(request)

        user = None
        try:
            authorization = request.headers.get('Authorization', None)
            if not authorization:
                raise KeyError
            if not authorization.startswith(self.jwt_auth.token_prefix):
                raise ValueError

            token = authorization.split(self.jwt_auth.token_prefix)[1]
            payload = self.jwt_auth.decode_jwt(token)
            user = self.jwt_auth.get_user(payload['sub'])
        except (IndexError, KeyError, ValueError, PyJWTError) as e:
            logger.debug(e)

        request.user = user if user else AnonymousUser
        response = self.get_response(request)

        return response
