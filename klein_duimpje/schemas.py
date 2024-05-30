from pydantic import BaseModel, HttpUrl
from typing import List, Optional


class VMBase(BaseModel):
    name: str
    VM_id: Optional[str] = None
    ip: Optional[str] = None

class VMCreate(VMBase):
    pass

class VM(VMBase):
    id: int
    owner_id: int

    class Config:
        orm_mode = True

class UserBase(BaseModel):
    email: str

class UserCreate(UserBase):
    password: str

class WebsiteBase(BaseModel):
    url: HttpUrl

class WebsiteCreate(WebsiteBase):
    pass

class Website(WebsiteBase):
    id: int
    owner_id: int

    class Config:
        orm_mode = True


class User(UserBase):
    id: int
    is_active: bool
    vms: List[VM] = []
    websites: List[Website] = []

    class Config:
        orm_mode = True

class UserUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    password: Optional[str] = None

