from datetime import datetime, timedelta

from django.conf import settings

from django.http import JsonResponse
from django.contrib.auth import get_user_model

import jwt


class JWTAuthentication:
    def __init__(self):
        yajwt = settings.YAJWT
        assert 'SECRET_KEY' in yajwt, 'Missing SECRET_KEY'
        assert 'COOKIE_DOMAIN' in yajwt, 'Missing COOKIE_DOMAIN'

        self.key = yajwt['SECRET_KEY']
        self.token_prefix = yajwt.get('TOKEN_PREFIX', 'Bearer') + ' '
        self.cookie_expires = yajwt.get('COOKIE_EXPIRES', None)

        self.cookie = {
            'key': yajwt.get('COOKIE_NAME', 'refreshtoken'),
            'path': yajwt.get('COOKIE_PATH', '/'),
            'domain': yajwt['COOKIE_DOMAIN'],
            'secure': yajwt.get('COOKIE_SECURE', True),
            'httponly': True,
            'samesite': yajwt.get('COOKIE_SAMESITE', 'Strict'),
            # expires will be updated before each cookie is set
            'expires': datetime.utcnow()
        }

        self.algorithm = yajwt.get('ALGORITHM', 'HS256')
        self.access_lifetime = yajwt.get(
            'ACCESS_LIFETIME', timedelta(minutes=15))
        self.refresh_lifetime = yajwt.get(
            'REFRESH_LIFETIME', timedelta(hours=24))

        self.UserModel = get_user_model()

    def tokens_response(self, user_id: int) -> JsonResponse:
        access_token = self.encode_jwt({'sub': user_id})
        refresh_token = self.encode_jwt({'sub': user_id}, audience='refresh')

        response = JsonResponse({'access_token': access_token})

        self.cookie['expires'] = datetime.utcnow()
        if self.cookie_expires is not None:
            self.cookie['expires'] += self.cookie_expires
        else:
            self.cookie['expires'] += self.refresh_lifetime

        response.set_cookie(value=refresh_token, **self.cookie)

        return response

    def get_user(self, user_id):
        return self.UserModel.objects.get(pk=user_id)

    def encode_jwt(self, payload, audience='access'):
        assert (audience == 'access' or audience == 'refresh'), \
               'audience must be access or refresh'
        assert isinstance(payload, dict), \
               'payload must be dictionary containing at least sub claim'
        assert 'sub' in payload, \
               'payload must contain sub claim'

        if audience == 'access':
            expires = self.access_lifetime
        else:
            expires = self.refresh_lifetime

        payload['aud'] = [audience]
        payload['iat'] = self._epoch()
        payload['exp'] = self._epoch(expires)

        return jwt.encode(
            payload, self.key, algorithm=self.algorithm).decode('utf-8')

    def decode_jwt(self, token, audience='access'):
        return jwt.decode(
            token,
            self.key,
            algorithm=self.algorithm,
            audience=audience,
            options={
                'require': ['aud', 'exp', 'sub', 'iat']
            }
        )

    def _epoch(self, arrow=timedelta(0)):
        return int((datetime.utcnow() + arrow).timestamp())
