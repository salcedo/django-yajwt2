# Django Yet Another JSON Web Token Middleware

```python
JWT_AUTH = {
    # Required
    'SECRET_KEY': 'muchsecretmanysecure',
    'COOKIE_DOMAIN': 'example.com',

    # Optional
    'COOKIE_EXPIRES': timedelta(hours=1) # same as REFRESH_LIFETIME if not set
    'COOKIE_NAME': 'refreshtoken',
    'COOKIE_PATH': '/',
    'COOKIE_SECURE': True,
    'COOKIE_SAMESITE': 'Stict',
    'TOKEN_PREFIX': 'Bearer',
    'ALGORITHM': 'HS256',
    'ACCESS_LIFETIME': timedelta(minutes=15),
    'REFRESH_LIFETIME': timedelta(hours=1),
}
```
