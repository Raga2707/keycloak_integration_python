import requests
from fastapi import APIRouter, Depends, Query, Body, HTTPException, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated, Union, Optional, List

from pydantic import SecretStr
from fastapi_keycloak import FastAPIKeycloak, OIDCUser, UsernamePassword, HTTPMethod, KeycloakUser, KeycloakGroup
import core.config
from dotenv import load_dotenv
import core.settings
from core.security import authenticate_user, get_current_user
from fastapi.responses import JSONResponse

setting = core.settings.Settings()

conf = core.config

load_dotenv()

auth_router = APIRouter()

# app = FastAPI()

# idp = FastAPIKeycloak(
#     server_url="http://observai-keycloak.apps.zagaopenshift.zagaopensource.com/realms/react-keycloak-login/protocol/openid-connect/auth",
#     client_id="react-client-auth",
#     client_secret="3adNftMWHlRTI0VQSEgbNOb7mIsKQXcH",
#     admin_client_secret="",
#     realm="react-keycloak-login",
#     callback_uri="http://localhost:5173/callback"
# )
# idp.add_swagger_config(app)

# Admin
# @auth_router.post("/proxy", tags=["admin-cli"])
# def proxy_admin_request(relative_path: str, method: HTTPMethod, additional_headers: dict = Body(None), payload: dict = Body(None)):
#     return idp.proxy(
#         additional_headers=additional_headers,
#         relative_path=relative_path,
#         method=method,
#         payload=payload
#     )

# @auth_router.get("/identity-providers", tags=["admin-cli"])
# def get_identity_providers():
#     return idp.get_identity_providers()


# @auth_router.get("/idp-configuration", tags=["admin-cli"])
# def get_idp_config():
#     return idp.open_id_configuration


# User Management

# @auth_router.get("/users", tags=["user-management"])
# def get_users():
#     return idp.get_all_users()


# @auth_router.get("/user", tags=["user-management"])
# def get_user_by_query(query: str = None):
#     return idp.get_user(query=query)


# @auth_router.post("/users", tags=["user-management"])
# def create_user(first_name: str, last_name: str, email: str, password: SecretStr, id: str = None):
#     return idp.create_user(first_name=first_name, last_name=last_name, username=email, email=email, password=password.get_secret_value(), id=id)


# @auth_router.get("/user/{user_id}", tags=["user-management"])
# def get_user(user_id: str = None):
#     return idp.get_user(user_id=user_id)

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# print(OAuth2PasswordBearer)
# print(oauth2_scheme, "OAUTH")

# class User(BaseModel):
#     username: str
#     email: Union[str, None] = None
#     full_name: Union[str, None] = None
#     disabled: Union[bool, None] = None

# def fake_decode_token(token):
#     print(token, "TOKEN")
#     return User(
#         username=token + "fakedecoded", email="john@example.com", full_name="John Doe"
#     )

# async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
#     user = fake_decode_token(token)
#     print(user, "FAKE TOKEN")
#     return user

# @auth_router.get("/users/me")
# async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
#     print(current_user, "RESPONSE")
#     return current_user

# @auth_router.get("/auth", tags=["test"])
# async def read_root():
#     return {"username": "alice"}

@auth_router.get("/environmentRoutes", tags=["test"])
async def env_var():
    return {
        "keycloak_url": conf.keycloak_url,
        "realm": setting.KEYCLOAK_URL
    }

@auth_router.post("/post", tags=["auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    print(user, "USER CRED")
    print(form_data, "FORM DATA")
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    # Generate token using Keycloak service
    access_token = ...
    return {"access_token": access_token, "token_type": "bearer"}
    print(user, "USER CRED")

# @auth_router.post("/auth/login", status_code=200, tags=["auth"])
# async def login_auth(
#     url: str = conf.keycloak_url,
#     grant_type: str = "password",
#     username: str = None,
#     password: str = None
# ):
#     # result_set = {
#     #     "url": url,
#     #     "grant_type": grant_type,
#     #     "username": username,
#     #     "password": password
#     # }
#     # return JSONResponse(content=result_set)
#     return username

@auth_router.post("/auth/login", status_code=status.HTTP_200_OK, tags=["auth"])
async def login_auth(username: str = None, password: str = None):
    if username is None or password is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and password are required.")

    token_url = conf.keycloak_url + "/token"
    payload = {
        "grant_type": "password",
        "client_id": conf.keycloak_clientID,
        "client_secret": conf.keycloak_clientAuth,
        "username": username,
        "password": password
    }

    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        token_data = response.json()
        return token_data
    except requests.RequestException as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="You are Unauthorized.")

@auth_router.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return current_user
