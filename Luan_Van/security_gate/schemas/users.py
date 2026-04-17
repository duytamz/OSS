from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime

# --- SCHEMAS CHO PROJECT ---
class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = None

class ProjectCreate(ProjectBase):
    pass

class ProjectResponse(ProjectBase):
    id: int
    org_id: int
    created_at: datetime

    class Config:
        from_attributes = True

# --- SCHEMAS CHO ORGANIZATION ---
class OrganizationBase(BaseModel):
    name: str

class OrganizationCreate(OrganizationBase):
    pass

class OrganizationResponse(OrganizationBase):
    id: int
    created_at: datetime
    projects: List[ProjectResponse] = []

    class Config:
        from_attributes = True

# --- SCHEMAS CHO USER ---
class UserBase(BaseModel):
    email: EmailStr
    full_name: str

class UserCreate(UserBase):
    password: str
    org_id: int

class UserResponse(UserBase):
    id: int
    is_active: bool
    org_id: int

    class Config:
        from_attributes = True

class UserBasicInfo(BaseModel):
    id: int
    full_name: str 
    email: EmailStr 

    class Config:
        from_attributes = True

class ProjectResponseSchema(BaseModel):
    id: int
    name: str
    organization_id: int
    creator: Optional[UserBasicInfo] = None 

    class Config:
        from_attributes = True 