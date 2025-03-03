import json
from typing import Dict, Any
from datetime import datetime

from ..lib.auth import Auth
from ..lib.response import Response
from ..lib.db import UserDB

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle user login with email and password"""
    try:
        # Parse request body
        body = json.loads(event.get('body', '{}'))
        
        # Extract login credentials
        email = body.get('email')
        password = body.get('password')
        
        # Validate required fields
        if not email or not password:
            return Response.error("Email and password are required", 400)
        
        # Authenticate user with Cognito
        login_result = Auth.login(email, password)
        
        if not login_result['success']:
            return Response.error(f"Login failed: {login_result.get('error')}", 401)
        
        # Get user from database
        user = UserDB.get_user_by_email(email)
        if not user:
            return Response.error("User not found", 404)
        
        # Update last login timestamp
        now = datetime.utcnow().isoformat()
        UserDB.update_user(
            user_id=user['id'],
            update_expression="SET lastLogin = :lastLogin",
            expression_attribute_values={
                ":lastLogin": now
            }
        )
        
        return Response.success(
            {
                "user": {
                    "id": user['id'],
                    "email": user['email'],
                    "name": user['name']
                },
                "tokens": {
                    "id_token": login_result['id_token'],
                    "access_token": login_result['access_token'],
                    "refresh_token": login_result['refresh_token'],
                    "expires_in": login_result['expires_in']
                }
            },
            "Login successful"
        )
    except Exception as e:
        return Response.error(f"Login failed: {str(e)}", 500)