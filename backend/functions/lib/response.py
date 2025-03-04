from typing import Any, Dict, Optional

def create_response(status_code: int, body: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Create a standardized API response"""
    response = {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': True,
            **(headers or {})
        },
        'body': body
    }
    return response

def success_response(data: Any = None, message: str = 'Success') -> Dict[str, Any]:
    """Create a success response"""
    body = {
        'success': True,
        'message': message
    }
    if data is not None:
        body['data'] = data
    return create_response(200, body)

def error_response(message: str, status_code: int = 400, error_code: Optional[str] = None) -> Dict[str, Any]:
    """Create an error response"""
    body = {
        'success': False,
        'message': message
    }
    if error_code:
        body['error_code'] = error_code
    return create_response(status_code, body)

def validation_error_response(errors: Dict[str, Any]) -> Dict[str, Any]:
    """Create a validation error response"""
    return error_response('Validation error', 400, 'VALIDATION_ERROR')

def unauthorized_response(message: str = 'Unauthorized') -> Dict[str, Any]:
    """Create an unauthorized response"""
    return error_response(message, 401, 'UNAUTHORIZED')

def forbidden_response(message: str = 'Forbidden') -> Dict[str, Any]:
    """Create a forbidden response"""
    return error_response(message, 403, 'FORBIDDEN')

def not_found_response(message: str = 'Resource not found') -> Dict[str, Any]:
    """Create a not found response"""
    return error_response(message, 404, 'NOT_FOUND')