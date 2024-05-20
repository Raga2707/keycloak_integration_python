# import requests
# from fastapi import APIRouter, Depends, Query, Body, HTTPException, status, Header, Response
# from pydantic import BaseModel
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from typing import Annotated, Union, Optional, List

# from pydantic import SecretStr
# from fastapi_keycloak import FastAPIKeycloak, OIDCUser, UsernamePassword, HTTPMethod, KeycloakUser, KeycloakGroup
# import core.config
# from dotenv import load_dotenv
# import core.settings
# from core.security import authenticate_user, get_current_user
# from fastapi.responses import JSONResponse

# setting = core.settings.Settings()

# conf = core.config

# load_dotenv()

# auth_router = APIRouter()

# class Data(BaseModel):
#     name: str
#     age: int

# @auth_router.post("/create")
# async def create(data: Data):
#     return {"data": data}

# @auth_router.get("/headers")
# def get_headers():
#     content = {"message": "Hello World"}
#     headers = {"X-Cat-Dog": "alone in the world", "Content-Language": "en-US"}
#     return JSONResponse(content=content, headers=headers)

