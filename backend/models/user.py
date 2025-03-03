from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, validator

class User(BaseModel):
    """User model representing a NounHub user"""
    id: str
    email: EmailStr
    name: str
    auth_provider: str  # "email", "google", or "apple"
    email_verified: bool = False
    created_at: str
    last_login: Optional[str] = None
    
    @validator('auth_provider')
    def validate_auth_provider(cls, v):
        allowed_providers = ["email", "google", "apple"]
        if v not in allowed_providers:
            raise ValueError(f"auth_provider must be one of {allowed_providers}")
        return v
    
    @classmethod
    def create(cls, id: str, email: str, name: str, auth_provider: str):
        """Create a new user with default values"""
        now = datetime.utcnow().isoformat()
        return cls(
            id=id,
            email=email,
            name=name,
            auth_provider=auth_provider,
            created_at=now,
            last_login=now
        )