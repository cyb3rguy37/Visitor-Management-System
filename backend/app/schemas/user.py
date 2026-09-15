# Defining user authentication and management using pydantic 

from datetime import datetime
from typing import Optional
from enum import Enum

from pydantic import BaseModel, EmailStr

class Role(str, Enum):
    admin="admin"
    manager= "manager"
    guard="guard"

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str
    role: Role

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str]= None