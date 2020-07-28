import json

from http import HTTPStatus

from django.conf.settings import JWT_AUTH

from django.http import HttpResponse
from django.views import View

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from django.contrib.auth import authenticate, login

from django_yajwt.auth import JWTAuthentication


class JWTAuthenticationTokenView(View):
    @method_decorator(csrf_exempt)
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

            jwt_auth = JWTAuthentication(settings=JWT_AUTH)
            return jwt_auth.get_tokens_response(user.id)
        else:
            return HttpResponse(status=HTTPStatus.UNAUTHORIZED)


class JWTAuthenticationRefreshView(View):
    def get(self, request):
        pass
