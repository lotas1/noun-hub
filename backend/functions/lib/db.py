import boto3
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError

class Database:
    """Database utility class for DynamoDB operations"""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
    
    def get_item(self, table_name: str, key: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Retrieve an item from DynamoDB table"""
        table = self.dynamodb.Table(table_name)
        try:
            response = table.get_item(Key=key)
            return response.get('Item')
        except ClientError as e:
            print(f"Error getting item from {table_name}: {e}")
            return None
    
    def put_item(self, table_name: str, item: Dict[str, Any]) -> bool:
        """Insert an item into DynamoDB table"""
        table = self.dynamodb.Table(table_name)
        try:
            table.put_item(Item=item)
            return True
        except ClientError as e:
            print(f"Error putting item to {table_name}: {e}")
            return False
    
    def update_item(self, table_name: str, key: Dict[str, Any], 
                    update_expression: str, expression_values: Dict[str, Any]) -> bool:
        """Update an item in DynamoDB table"""
        table = self.dynamodb.Table(table_name)
        try:
            table.update_item(
                Key=key,
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values
            )
            return True
        except ClientError as e:
            print(f"Error updating item in {table_name}: {e}")
            return False
    
    def delete_item(self, table_name: str, key: Dict[str, Any]) -> bool:
        """Delete an item from DynamoDB table"""
        table = self.dynamodb.Table(table_name)
        try:
            table.delete_item(Key=key)
            return True
        except ClientError as e:
            print(f"Error deleting item from {table_name}: {e}")
            return False

# Create a singleton instance
db = Database()