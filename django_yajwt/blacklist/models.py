from django.db import models


class TokenBlacklist(models.Model):
    token = models.TextField(unique=True, null=False)
    expires = models.IntegerField(default=0)
