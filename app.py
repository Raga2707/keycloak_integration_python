from typing import Union
from fastapi import FastAPI
from api.trace_queryapi import log_router
from api.keycloak_authapi import auth_router
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.include_router(log_router)
app.include_router(auth_router)

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
