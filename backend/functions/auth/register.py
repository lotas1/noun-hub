import json
import uuid
from typing import Dict, Any

from ..lib.auth import Auth
from ..lib.response import Response
from ..lib.db import UserDB
from ...models.user import User

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle user registration with email and password"""
    try:
        # Parse request body
        body = json.loads(event.get('body', '{}'))
        
        # Extract registration data
        email = body.get('email')
        password = body.get('password')
        name = body.get('name')
        
        # Validate required fields
        if not email or not password or not name:
            return Response.error("Email, password, and name are required", 400)
        
        # Check if user already exists
        existing_user = UserDB.get_user_by_email(email)
        if existing_user:
            return Response.error("User with this email already exists", 400)
        
        # Register user with Cognito
        user_id = str(uuid.uuid4())
        registration = Auth.register_user(email, password, name)
        
        if not registration['success']:
            return Response.error(f"Registration failed: {registration.get('error')}", 400)
        
        # Create user in database
        user = User.create(
            id=registration['user_id'],
            email=email,
            name=name,
            auth_provider="email"
        )
        
        UserDB.create_user(user.dict())
        
        return Response.success(
            {
                "user_id": user.id,
                "email": user.email,
                "name": user.name,
                "message": "User registered successfully. Please check your email for verification code."
            },
            "Registration successful"
        )
    except Exception as e:
        return Response.error(f"Registration failed: {str(e)}", 500)