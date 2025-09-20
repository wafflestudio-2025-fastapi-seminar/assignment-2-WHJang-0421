import datetime
from typing import Annotated
import jwt
from src.users.errors import (
    BadAuthHeaderException,
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
import argon2
from fastapi import APIRouter
from fastapi import Depends, Cookie

from src.auth.schemas import LoginRequest, LoginResponse
from src.common.database import blocked_token_db, session_db, user_db
import jwt
from src.users.errors import InvalidAccountException
from datetime import datetime, timedelta, timezone
from src.auth.password_hash import password_hasher
import secrets

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

SECRET_KEY = secrets.token_bytes(
    32
)  # use an in-memory secret key. we use an in-memory db anyway


@auth_router.post("/token")
def login(request: LoginRequest) -> LoginResponse:
    try:
        for i, user_dict in enumerate(user_db):
            if user_dict["email"] == request.email:
                password_hasher.verify(user_dict["hashed_password"], request.password)
                # create access token
                access_token_claims = {
                    "sub": f"user {i}",
                    "exp": int(
                        (
                            datetime.now(tz=timezone.utc)
                            + timedelta(minutes=SHORT_SESSION_LIFESPAN)
                        ).timestamp()
                    ),
                }
                access_token = jwt.encode(
                    access_token_claims, SECRET_KEY, algorithm="HS256"
                )
                # create refresh token
                refresh_token_claims = {
                    "sub": f"user {i}",
                    "exp": int(
                        (
                            datetime.now(tz=timezone.utc)
                            + timedelta(minutes=LONG_SESSION_LIFESPAN)
                        ).timestamp()
                    ),
                }
                refresh_token = jwt.encode(
                    refresh_token_claims, SECRET_KEY, algorithm="HS256"
                )
                return LoginResponse(
                    access_token=access_token, refresh_token=refresh_token
                )
    except argon2.exceptions.VerifyMismatchError:
        raise InvalidAccountException()
    raise InvalidAccountException()


bearer_scheme = HTTPBearer(auto_error=False)


@auth_router.post("/token/refresh")
def refresh(
    credential: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> LoginResponse:
    if not credential:
        raise UnauthenticatedException()
    if credential.scheme != "Bearer":
        raise BadAuthHeaderException()

    token = credential.credentials
    if token in blocked_token_db.keys():
        raise InvalidTokenException()

    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise InvalidTokenException()

    try:
        user_id = decoded_token["sub"]
        user_id = int(user_id[-1])
        exp_time = decoded_token["exp"]
    except Exception:
        raise InvalidTokenException()

    blocked_token_db[token] = exp_time

    # create access token
    access_token_claims = {
        "sub": f"user {user_id}",
        "exp": int(
            (
                datetime.now(tz=timezone.utc)
                + timedelta(minutes=SHORT_SESSION_LIFESPAN)
            ).timestamp()
        ),
    }
    access_token = jwt.encode(access_token_claims, SECRET_KEY, algorithm="HS256")
    # create refresh token
    refresh_token_claims = {
        "sub": f"user {user_id}",
        "exp": int(
            (
                datetime.now(tz=timezone.utc) + timedelta(minutes=LONG_SESSION_LIFESPAN)
            ).timestamp()
        ),
    }
    decoded_token = jwt.encode(refresh_token_claims, SECRET_KEY, algorithm="HS256")
    return LoginResponse(access_token=access_token, refresh_token=decoded_token)


# @auth_router.delete("/token")
#
#
# @auth_router.post("/session")
#
#
# @auth_router.delete("/session")
