from datetime import datetime, timedelta

from django.contrib.auth import get_user_model

import jwt


class JWTAuthentication:
    def __init__(self, settings):
        assert 'SECRET_KEY' in settings, "Missing SECRET_KEY"

        self.key = settings['SECRET_KEY']
        self.token_prefix = settings.get('TOKEN_PREFIX', 'Bearer') + ' '

        self.algorithm = settings.get('ALGORITHM', 'HS256')
        self.access_lifetime = settings.get(
            'ACCESS_LIFETIME', timedelta(minutes=15))
        self.refresh_lifetime = settings.get(
            'REFRESH_LIFETIME', timedelta(hours=24))

        self.UserModel = get_user_model()

    def get_access_token(self, user_id):
        return self.encode_jwt({'sub': user_id})

    def get_refresh_token(self, user_id):
        return self.encode_jwt({'sub': user_id}, audience='refresh')

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
            expiration = self.access_lifetime
        else:
            expiration = self.refresh_lifetime

        payload['aud'] = [audience]
        payload['iat'] = self._epoch()
        payload['exp'] = self._epoch(expiration)

        return jwt.encode(payload, self.key, algorithm=self.algorithm)

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
