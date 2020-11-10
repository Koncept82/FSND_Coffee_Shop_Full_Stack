import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen
import re


AUTH0_DOMAIN = 'dev-6fc997z5.eu.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffee-shop'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def get_token_auth_header():
    if 'Authorization' not in request.headers:
        raise AuthError({"code": "authorization_header_missing",
                         "description": 
                         "Authorization header is expected"}, 401)

    auth_header = request.headers['Authorization']
    header_parts = auth_header.split()

    if header_parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                         "description":
                         "Authorization header must start with"
                         " Bearer"}, 401)
    elif len(header_parts) == 1:
        raise AuthError({"code": "invalid_header",
                         "description": "Token not found"}, 401)
    elif len(header_parts) > 2:
        raise AuthError({"code": "invalid_header",
                         "description":
                         "Authorization header must be"
                         " Bearer token"}, 401)

    return header_parts[1]


def check_permissions(permission, payload):
    print(payload)
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permissions not included in JWT.'
        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not found.'
        }, 403)
    return True


def verify_decode_jwt(token):
    token = get_token_auth_header()
    jsonurl = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer="https://"+AUTH0_DOMAIN+"/"
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                             "incorrect claims,"
                             "please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                             "Unable to parse authentication"
                             " token."}, 401)


def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator