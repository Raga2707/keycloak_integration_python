import requests
from fastapi import APIRouter, Depends, Query, Body, HTTPException, status, Header, Response
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

class Data(BaseModel):
    name: str
    age: int

@auth_router.post("/create")
async def create(data: Data):
    return {"data": data}

@auth_router.get("/environmentRoutes", tags=["test"])
async def env_var():
    return {
        "keycloak_url": conf.keycloak_url,
        "realm": setting.KEYCLOAK_URL
    }

@auth_router.post("/post", tags=["test-auth"])
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

access_token = None
refresh_token = None
@auth_router.post("/auth/login", status_code=status.HTTP_200_OK, tags=["auth"])
async def login_auth(username: str = None, password: str = None):
    global refresh_token
    if username is None or password is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and password are required.")

    token_url = conf.keycloak_url + "/token"
    payload = {
        "grant_type": "password",
        # "scope": "openid",
        "client_id": conf.keycloak_clientID,
        "client_secret": conf.keycloak_clientAuth,
        "username": username,
        "password": password
    }

    try:
        response = requests.post(token_url, data=payload)
        print(response.json(), "RESPONSE KEYCLOAK")
        response.raise_for_status()
        print(response.raise_for_status, "LOGIN RAISE")
        token_data = response.json()
        print(token_data)
        refresh_token = token_data.get("refresh_token")  
        access_token = token_data.get("access_token")
        print(token_data.get("refresh_token"), "PRINT TOKEN")
        return token_data
    except requests.RequestException as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="You are Unauthorized.")
        # raise e

@auth_router.get("/users/me", tags=["test"])
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return current_user

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")
# print(oauth2_scheme.model, "LOGIN TOKEN")

# @auth_router.post("/logout", tags=["auth"])
# async def logout(refresh_token: str = Depends(oauth2_scheme)):
#     # Revoke the tokens associated with the refresh token
    
#     # revoked = revoke_tokens(refresh_token, data=payload)
#     revoked = revoke_tokens(refresh_token)

#     payload = {
#         "client_id": conf.keycloak_clientID,
#         "client_secret": conf.keycloak_clientAuth,
#         "refresh_token": revoked
#     }
#     print(revoke_tokens, "TOKEN")
#     print(revoked, "LOGOUT------------REVOKE")
#     if revoked:
#         return {"message": "Logout successful"}
#     else:
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to logout")

# # Assume revoke_tokens function is implemented to revoke tokens
# def revoke_tokens(refresh_token: str) -> bool:
#     # Send a request to Keycloak to revoke the refresh token
#     print(refresh_token, "REFRESH")
#     revoke_url = conf.keycloak_url + "/logout"
#     headers = {"Authorization": "Bearer " + refresh_token, "Content-Type": "application/x-www-form-urlencoded"}
#     payload = {
#         "client_id": conf.keycloak_clientID,
#         "client_secret": conf.keycloak_clientAuth,
#         "refresh_token": revoked
#     }
#     try:
#         response = requests.get(revoke_url, headers=headers, data=payload)
#         print(response.json(), "LOGOUT")
#         response.raise_for_status()
#         return True
#     except requests.RequestException as e:
#         # Handle error
#         print(e)
#         return False

print(OAuth2PasswordBearer, "BEARER TOKEN")
# @auth_router.post("/auth/logout", status_code=status.HTTP_200_OK, tags=["auth"])
# async def logout_auth():
#     global refresh_token
#     global access_token
#     print(refresh_token, "REFRESH TOKEN LOGOUT")

#     if refresh_token is None:
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Refresh token is required for logout.")

#     logout_url = conf.keycloak_url + "/logout"
#     headers = {
#         "Authorization": f"Bearer {access_token}",
#         "Content-Type": "application/x-www-form-urlencoded"
#     }
#     payload = {
#         "client-id": conf.keycloak_clientID,
#         "client-secret": conf.keycloak_clientAuth,
#         "refresh_token": refresh_token
#     }

#     try:
#         response = requests.post(logout_url, headers=headers, data=payload)
#         response.raise_for_status()
#         print(response.raise_for_status, "LOGOUT RAISE")
#         return {"message": "Logged out successfully"}
#     except requests.RequestException as e:
#         raise e
        # raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to logout.")

def logout():
    global refresh_token
    try:
        headers = {
            # "Authorization" : f"Bearer {access_token}",
            # "Authorization" : "Bearer",
            # "Content-Type": "application/x-www-form-urlencoded"
            "Access-Control-Allow-Headers": "*"
        }

        payload = {
            "client_id": conf.keycloak_clientID,
            "client_secret": conf.keycloak_clientAuth,
            "refresh_token": refresh_token
        }

        logout_url = conf.keycloak_url + "/logout"
        response = requests.post(logout_url, 
        # headers={"WWW-Authenticate": "Bearer"}, 
        data=payload)
        response.raise_for_status()
        print(logout_url)
        print("Logged out successfully")

    except requests.RequestException as e:
        print("Failed to logout:", e)
        raise

# def logout(refresh_token):
#     try:
#         payload = {
#             "client_id": conf.keycloak_clientID,
#             "client_secret": conf.keycloak_clientAuth,
#             "refresh_token": refresh_token
#         }

#         logout_auth(payload)
#     except Exception as e:
#         print(e)
#         raise e

@auth_router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["auth"])
async def logout_auth(response: Response):
    # global access_token
    # global refresh_token
    # headers = {
    #         "Authorization" : f"Bearer {access_token}",
    #         # "Authorization" : "Bearer",
    #         "Content-Type": "application/x-www-form-urlencoded"
    #     }
    print(refresh_token, "REFRESH TOKEN LOGOUT")

    if refresh_token is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
        # headers=headers, 
        detail="Refresh token is required for logout.")

    logout()
    print(refresh_token, "LOGOUT RESPO")
    return {"message": "Logged out successfully"}

# @auth_router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["auth"])
# async def logout_auth(payload):
#     headers = {
#         "Authorization" : f"Bearer {access_token}",
#         # "Authorization" : "Bearer",
#         "Content-Type": "application/x-www-form-urlencoded"
#     }
#     logout_url = conf.keycloak_url + "/logout"

#     response = requests.post(logout_url, data=payload, headers=headers)

#     if response.status_code == 204:
#         print("Logout Successful")
#         return {"message": "Logged Out Successfully"}
#     else:
#         print("Logout failed")
#         return {"message": "Logout failed"}
# logout(refresh_token)

@auth_router.get("/headers")
def get_headers():
    content = {"message": "Hello World"}
    headers = {"X-Cat-Dog": "alone in the world", "Content-Language": "en-US"}
    return JSONResponse(content=content, headers=headers)

