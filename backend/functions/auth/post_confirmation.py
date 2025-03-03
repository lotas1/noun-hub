import json
import os
from typing import Dict, Any

from ..lib.db import UserDB

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle post confirmation trigger from Cognito
    
    This function is triggered after a user confirms their email address.
    It creates or updates the user record in DynamoDB.
    """
    try:
        print("Post confirmation handler started")
        print(f"Event received: {json.dumps(event)}")
        
        # Extract user attributes from the event
        user_attributes = event['request']['userAttributes']
        print(f"User attributes: {json.dumps(user_attributes)}")
        
        user_id = user_attributes['sub']
        email = user_attributes['email']
        name = user_attributes.get('name', email.split('@')[0])  # Use part of email as name if not provided
        
        print(f"Extracted user data - ID: {user_id}, Email: {email}, Name: {name}")
        
        # Create user record in DynamoDB
        user_data = {
            'id': user_id,
            'email': email,
            'name': name,
            'auth_provider': 'email'
        }
        print(f"Attempting to create user in DynamoDB with data: {json.dumps(user_data)}")
        
        UserDB.create_user(user_data)
        print("User successfully created in DynamoDB")
        
        return event
        
    except Exception as e:
        print(f"Error in post confirmation handler: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        print(f"Error details: {repr(e)}")
        raise e