import re

from pydantic import BaseModel, field_validator, EmailStr
from fastapi import HTTPException
from src.common.database import user_db

from src.users.errors import (
    BioTooLongException,
    EmailExistsException,
    InvalidPasswordException,
    InvalidPhoneNumberException,
)


class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone_number: str
    bio: str | None = None
    height: float

    @field_validator("password", mode="after")
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 20:
            raise InvalidPasswordException
        return v

    @field_validator("phone_number", mode="after")
    def validate_phone_number(cls, v):
        pattern = re.compile("010-[0-9]{4}-[0-9]{4}")
        match = pattern.match(v)

        if match != None and match.span() == (0, len(v)):
            return v
        else:
            raise InvalidPhoneNumberException

    @field_validator("bio", mode="after")
    def validate_bio(cls, v):
        if v == None or len(v) <= 500:
            return v
        else:
            raise BioTooLongException

    @field_validator("email", mode="after")
    def validate_email(cls, v):
        if v in [user_dict["email"] for user_dict in user_db]:
            raise EmailExistsException
        else:
            return v


class UserResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    bio: str | None = None
    height: float
