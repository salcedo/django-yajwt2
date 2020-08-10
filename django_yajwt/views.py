import json

from http import HTTPStatus

from django.http import HttpResponse
from django.views import View

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from django.contrib.auth import authenticate, login

from jwt import PyJWTError

from django_yajwt.auth import JWTAuthentication


@method_decorator(csrf_exempt, name='dispatch')
class JWTAuthenticationLoginView(View):
    def post(self, request):
        try:
            body = json.loads(request.body.decode('utf-8'))
            username = body['username']
            password = body['password']
        except (KeyError, TypeError, json.decoder.JSONDecodeError):
            return HttpResponse(status=HTTPStatus.BAD_REQUEST)

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)

            jwt_auth = JWTAuthentication()
            return jwt_auth.tokens_response(user.id)
        else:
            return HttpResponse(status=HTTPStatus.UNAUTHORIZED)


class JWTAuthenticationRefreshView(View):
    def get(self, request):
        jwt_auth = JWTAuthentication()

        token = request.COOKIES.get(jwt_auth.cookie['key'], None)
        if token is None:
            return HttpResponse(status=HTTPStatus.BAD_REQUEST)

        try:
            payload = jwt_auth.decode_jwt(token, audience='refresh')
            user = jwt_auth.get_user(payload['sub'])
            if user is None:
                raise ValueError
        except (IndexError, ValueError, PyJWTError):
            return HttpResponse(status=HTTPStatus.UNAUTHORIZED)

        return jwt_auth.tokens_response(user.id)
