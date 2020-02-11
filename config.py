import os
import urllib.parse

API_VERSION = 1
DEBUG = False

# FOR PRODUCTION
MONGO_DBNAME = str(os.environ['DATABASE_NAME'])
DATABASE_URL = str(os.environ['DATABASE_URL'])
DATABASE_USER = str(os.environ['DATABASE_USER'])
DATABASE_PASSWORD = str(os.environ['DATABASE_PASSWORD'])
SECRET_KEY = str(os.environ['SECRET_KEY'])

KEYCLOAK_URL = str(os.environ['KEYCLOAK_URL'])
KEYCLOAK_REALM = str(os.environ['KEYCLOAK_REALM'])
KEYCLOAK_CLIENT_ID = str(os.environ['KEYCLOAK_CLIENT_ID'])
KEYCLOAK_CLIENT_SECRET = str(os.environ['KEYCLOAK_CLIENT_SECRET'])


MONGO_URI = 'mongodb://' + str(urllib.parse.quote_plus(DATABASE_USER)) + ':' + \
            str(urllib.parse.quote_plus(DATABASE_PASSWORD)) + '@' + str(urllib.parse.quote_plus(DATABASE_URL)) + \
            '/' + str(urllib.parse.quote_plus(MONGO_DBNAME))
