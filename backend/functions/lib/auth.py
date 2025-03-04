import boto3
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError

class Auth:
    """Authentication utility class for AWS Cognito operations"""
    
    def __init__(self):
        self.cognito = boto3.client('cognito-idp')
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return user claims"""
        try:
            response = self.cognito.get_user(AccessToken=token)
            user_attributes = {attr['Name']: attr['Value'] for attr in response['UserAttributes']}
            return {
                'sub': user_attributes.get('sub'),
                'email': user_attributes.get('email'),
                'name': user_attributes.get('name'),
                'email_verified': user_attributes.get('email_verified') == 'true'
            }
        except ClientError as e:
            print(f"Error verifying token: {e}")
            return None
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user details from Cognito"""
        try:
            response = self.cognito.admin_get_user(
                UserPoolId=self.get_user_pool_id(),
                Username=user_id
            )
            user_attributes = {attr['Name']: attr['Value'] for attr in response['UserAttributes']}
            return {
                'id': user_id,
                'email': user_attributes.get('email'),
                'name': user_attributes.get('name'),
                'email_verified': user_attributes.get('email_verified') == 'true',
                'created_at': response['UserCreateDate'].isoformat(),
                'last_login': response.get('UserLastModifiedDate', '').isoformat()
            }
        except ClientError as e:
            print(f"Error getting user {user_id}: {e}")
            return None
    
    def get_user_pool_id(self) -> str:
        """Get the Cognito User Pool ID from environment variables"""
        import os
        return os.environ.get('USER_POOL_ID', '')

# Create a singleton instance
auth = Auth()