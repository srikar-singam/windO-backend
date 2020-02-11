import os
import json
from flask import Flask
from flask_pymongo import PyMongo
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config.from_pyfile('dev-config.py')

# CREATE CLIENT SECRET JSON
client_secret_json = {
    "web": {
        "issuer": str(app.config['KEYCLOAK_URL']) + "/auth/realms/" + str(app.config['KEYCLOAK_REALM']),
        "auth_uri": str(app.config['KEYCLOAK_URL']) + "/auth/realms/" + str(app.config['KEYCLOAK_REALM']) +
        "/protocol/openid-connect/auth",
        "client_id": str(app.config['KEYCLOAK_CLIENT_ID']),
        "client_secret": str(app.config['KEYCLOAK_CLIENT_SECRET']),
        "redirect_uris": ["*"],
        "userinfo_uri": str(app.config['KEYCLOAK_URL']) + "/auth/realms/" + str(app.config['KEYCLOAK_REALM']) +
        "/protocol/openid-connect/userinfo",
        "token_uri": str(app.config['KEYCLOAK_URL']) + "/auth/realms/" + str(app.config['KEYCLOAK_REALM']) +
        "/protocol/openid-connect/token",
        "token_introspection_uri": str(app.config['KEYCLOAK_URL']) +
        "/auth/realms/" + str(app.config['KEYCLOAK_REALM']) + "/protocol/openid-connect/token/introspect",
        "bearer_only": "true"
    }
}

with open('/home/rudra/PycharmProjects/python3-keycloak-template/client_secrets.json', 'w') as f:
    json.dump(client_secret_json, f)

app.config.update({
    'SECRET_KEY': str(app.config['KEYCLOAK_CLIENT_SECRET']),
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'OIDC_TOKEN_TYPE_HINT': 'access_token'
})

mongo = PyMongo(app)

from routes import *

if __name__ == '__main__':
    app.run('0.0.0.0', 3003)
