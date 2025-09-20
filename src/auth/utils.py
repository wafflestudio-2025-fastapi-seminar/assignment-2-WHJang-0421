import jwt
from fastapi import Depends
from typing import Optional
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.auth.router import SECRET_KEY
from src.users.errors import (
    BadAuthHeaderException,
    UnauthenticatedException,
    InvalidTokenException,
)

bearer_scheme = HTTPBearer(auto_error=False)


def validate_token_and_extract_user_id(
    credential: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> int:
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

    return user_id

