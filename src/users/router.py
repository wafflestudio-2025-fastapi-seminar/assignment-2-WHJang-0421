from typing import Annotated
import jwt
from src.auth.router import SECRET_KEY
from src.users.errors import (
    BadAuthHeaderException,
    UnauthenticatedException,
    InvalidTokenException,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi import Depends
from typing import Optional

from fastapi import APIRouter, Depends, Cookie, Header, status

from src.auth.utils import validate_token_and_extract_user_id
from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import blocked_token_db, session_db, user_db
from argon2 import PasswordHasher
from src.auth.password_hash import password_hasher


user_router = APIRouter(prefix="/users", tags=["users"])


@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    user_dict = vars(request)
    user_dict["hashed_password"] = password_hasher.hash(user_dict["password"])
    del user_dict["password"]
    user_db.append(user_dict)
    return UserResponse(user_id=len(user_db) - 1, **user_dict)


bearer_scheme = HTTPBearer(auto_error=False)


@user_router.get("/me")
def get_user_info(
    credential: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> UserResponse:
    if not credential:
        raise UnauthenticatedException()
    if credential.scheme != "Bearer":
        raise BadAuthHeaderException()

    token = credential.credentials
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError as e:
        print(type(e))
        print(e)
        raise InvalidTokenException()

    try:
        user_id = decoded_token["sub"]
        user_id = int(user_id[-1])
    except Exception:
        raise InvalidTokenException()

    user_dict = user_db[user_id]
    return UserResponse(user_id=user_id, **user_dict)
