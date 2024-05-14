from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    KEYCLOAK_URL: str
    KEYCLOAK_REALM: str
