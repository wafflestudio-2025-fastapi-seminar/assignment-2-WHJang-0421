from typing import Annotated
from datetime import datetime, timezone
import jwt
from src.auth.router import SECRET_KEY
from src.users.errors import (
    BadAuthHeaderException,
    InvalidSessionException,
    UnauthenticatedException,
    InvalidTokenException,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi import Depends
from typing import Optional

from fastapi import APIRouter, Depends, Cookie, Header, status

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
    sid: Annotated[str | None, Cookie()] = None,
    authorization: Annotated[str | None, Header()] = None,
    credential: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> UserResponse:
    if sid:
        if sid not in session_db.keys():
            raise InvalidSessionException()
        if datetime.now(tz=timezone.utc) > session_db[sid][0]:
            raise InvalidSessionException()
        user_id = session_db[sid][1]
        user_dict = user_db[user_id]
        return UserResponse(user_id=user_id, **user_dict)

    if not authorization:
        raise UnauthenticatedException()
    if not credential:
        raise BadAuthHeaderException()
    if credential.scheme != "Bearer":
        raise BadAuthHeaderException()

    token = credential.credentials
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise InvalidTokenException()

    try:
        user_id = decoded_token["sub"]
        user_id = int(user_id[-1])
    except Exception:
        raise InvalidTokenException()

    user_dict = user_db[user_id]
    return UserResponse(user_id=user_id, **user_dict)
