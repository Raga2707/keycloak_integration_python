from typing import Union
from fastapi import FastAPI
from api.trace_queryapi import log_router
from api.keycloak_authapi import auth_router

app = FastAPI()

app.include_router(log_router)
app.include_router(auth_router)

# @app.get("/")
# async def read_root():
#     return {"Hello": "World"}

# @app.get("/hello")
# async def hello_python():
#     return {"Hello": "Python"}

# @app.get("/items/{item_id}")
# async def read_item(item_id: int, q: Union[str, None] = None):
#     return {"item_id": item_id, "q": q}