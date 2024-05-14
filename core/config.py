import os
from dotenv import load_dotenv

load_dotenv()

keycloak_url = os.getenv("KEYCLOAK_URL")
keycloak_realm = os.getenv("KEYCLOAK_REALM")
keycloak_clientID = os.getenv("KEYCLOAK_CLIENT_ID")
keycloak_clientAuth = os.getenv("KEYCLOAK_CLIENT_AUTH")

# print(os.getenv("KEYCLOAK_URL"))
# print(keycloak_url)
# print(keycloak_realm)
# print(keycloak_clientID)
# print(keycloak_clientAuth)
