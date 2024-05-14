from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
# from config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

def authenticate_user(username: str, password: str):
    if username == "admin" and password == "admin":
        return {"username": username}
    else:
        return "User Not Authenticated"

def get_current_user(token: str = Depends(oauth2_scheme)):
    if token == "valid_token":
        return {"username": "admin"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
