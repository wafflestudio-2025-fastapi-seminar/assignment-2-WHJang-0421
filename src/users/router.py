from typing import Annotated

from fastapi import APIRouter, Depends, Cookie, Header, status

from src.users.schemas import CreateUserRequest, UserResponse
from argon2 import PasswordHasher
from src.common.database import blocked_token_db, session_db, user_db

user_router = APIRouter(prefix="/users", tags=["users"])
password_hasher = PasswordHasher()


@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    user_dict = vars(request)
    user_dict["hashed_password"] = password_hasher.hash(user_dict["password"])
    del user_dict["password"]
    user_db.append(user_dict)
    return UserResponse(user_id=len(user_db)-1, **user_dict)


@user_router.get("/me")
def get_user_info():
    pass
