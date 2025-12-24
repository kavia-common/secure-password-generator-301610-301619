from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from src.api.models import (
    PasswordGenerationRequest,
    PasswordGenerationResponse,
    ErrorResponse,
    HealthResponse
)
from src.api.password_service import PasswordGenerationService

# FastAPI app initialization with metadata for OpenAPI documentation
app = FastAPI(
    title="Secure Password Generator API",
    description="REST API for generating secure random passwords with customizable criteria",
    version="1.0.0",
    openapi_tags=[
        {
            "name": "health",
            "description": "Health check and service status endpoints"
        },
        {
            "name": "password",
            "description": "Password generation endpoints"
        }
    ]
)

# CORS middleware configuration - allows frontend on port 3000
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://localhost:3000",
        "http://127.0.0.1:3000",
        "https://127.0.0.1:3000",
        "*"  # Allow all origins for development
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# PUBLIC_INTERFACE
@app.get(
    "/",
    response_model=HealthResponse,
    tags=["health"],
    summary="Health Check",
    description="Check if the service is running and healthy"
)
def health_check():
    """
    Health check endpoint to verify service availability.
    
    Returns:
        HealthResponse with status and message
    """
    return HealthResponse(
        status="healthy",
        message="Secure Password Generator API is running"
    )


# PUBLIC_INTERFACE
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["health"],
    summary="Detailed Health Check",
    description="Detailed health status of the password generation service"
)
def detailed_health_check():
    """
    Detailed health check endpoint with additional service information.
    
    Returns:
        HealthResponse with detailed status information
    """
    return HealthResponse(
        status="healthy",
        message="All systems operational. Password generation service ready."
    )


# PUBLIC_INTERFACE
@app.post(
    "/api/generate-password",
    response_model=PasswordGenerationResponse,
    responses={
        200: {
            "description": "Password generated successfully",
            "model": PasswordGenerationResponse
        },
        400: {
            "description": "Invalid request parameters",
            "model": ErrorResponse
        },
        422: {
            "description": "Validation error",
            "model": ErrorResponse
        }
    },
    tags=["password"],
    summary="Generate Secure Password",
    description=(
        "Generate a secure random password based on specified criteria. "
        "Users can customize the length and character types included in the password."
    )
)
def generate_password(request: PasswordGenerationRequest):
    """
    Generate a secure random password with user-specified options.
    
    The password is generated using cryptographically secure random number generation
    (secrets module) to ensure high-quality randomness suitable for security purposes.
    
    Args:
        request: PasswordGenerationRequest containing:
            - length: Password length (8-128 characters, default: 16)
            - include_uppercase: Include uppercase letters A-Z (default: True)
            - include_lowercase: Include lowercase letters a-z (default: True)
            - include_numbers: Include digits 0-9 (default: True)
            - include_special: Include special characters (default: True)
    
    Returns:
        PasswordGenerationResponse containing:
            - password: The generated secure password
            - length: Actual length of the generated password
            - options_used: Dictionary of the options that were applied
    
    Raises:
        HTTPException: 400 error if validation fails or no character types selected
    """
    try:
        # Generate password using the service
        response = PasswordGenerationService.generate_password(request)
        return response
        
    except ValueError as e:
        # Handle validation errors
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Invalid password generation request",
                "detail": str(e)
            }
        )
    except Exception as e:
        # Handle unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Internal server error during password generation",
                "detail": str(e)
            }
        )


# PUBLIC_INTERFACE
@app.get(
    "/api/password-options",
    tags=["password"],
    summary="Get Password Generation Options",
    description="Retrieve the available options and constraints for password generation"
)
def get_password_options():
    """
    Get information about available password generation options and constraints.
    
    Returns:
        Dictionary containing available options, constraints, and defaults
    """
    return {
        "length": {
            "min": 8,
            "max": 128,
            "default": 16,
            "description": "Length of the password in characters"
        },
        "character_types": {
            "uppercase": {
                "default": True,
                "description": "Include uppercase letters (A-Z)"
            },
            "lowercase": {
                "default": True,
                "description": "Include lowercase letters (a-z)"
            },
            "numbers": {
                "default": True,
                "description": "Include numbers (0-9)"
            },
            "special": {
                "default": True,
                "description": "Include special characters (!@#$%^&*()-_=+[]{}|;:,.<>?)"
            }
        },
        "constraints": {
            "at_least_one_type_required": True,
            "description": "At least one character type must be selected"
        }
    }


# Custom exception handler for better error responses
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """
    Custom exception handler to ensure consistent error response format.
    
    Args:
        request: The incoming request
        exc: The HTTPException that was raised
        
    Returns:
        JSONResponse with error details
    """
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail if isinstance(exc.detail, dict) else {"error": str(exc.detail)}
    )
