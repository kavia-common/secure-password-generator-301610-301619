from pydantic import BaseModel, Field, field_validator
from typing import Optional


class PasswordGenerationRequest(BaseModel):
    """Request model for password generation with user-specified criteria."""
    
    length: int = Field(
        default=16,
        ge=8,
        le=128,
        description="Length of the password to generate (8-128 characters)"
    )
    include_uppercase: bool = Field(
        default=True,
        description="Include uppercase letters (A-Z)"
    )
    include_lowercase: bool = Field(
        default=True,
        description="Include lowercase letters (a-z)"
    )
    include_numbers: bool = Field(
        default=True,
        description="Include numbers (0-9)"
    )
    include_special: bool = Field(
        default=True,
        description="Include special characters (!@#$%^&*)"
    )
    
    @field_validator('length')
    @classmethod
    def validate_length(cls, v):
        """Validate that password length is within acceptable range."""
        if v < 8:
            raise ValueError('Password length must be at least 8 characters')
        if v > 128:
            raise ValueError('Password length must not exceed 128 characters')
        return v
    
    def validate_at_least_one_option(self):
        """Ensure at least one character type is selected."""
        if not any([
            self.include_uppercase,
            self.include_lowercase,
            self.include_numbers,
            self.include_special
        ]):
            raise ValueError(
                'At least one character type must be selected '
                '(uppercase, lowercase, numbers, or special characters)'
            )


class PasswordGenerationResponse(BaseModel):
    """Response model containing the generated password and the options used."""
    
    password: str = Field(
        description="The generated secure password"
    )
    length: int = Field(
        description="Length of the generated password"
    )
    options_used: dict = Field(
        description="The character type options that were used to generate the password"
    )


class ErrorResponse(BaseModel):
    """Error response model for validation and other errors."""
    
    error: str = Field(
        description="Error message describing what went wrong"
    )
    detail: Optional[str] = Field(
        default=None,
        description="Additional details about the error"
    )


class HealthResponse(BaseModel):
    """Health check response model."""
    
    status: str = Field(
        description="Health status of the service"
    )
    message: str = Field(
        description="Additional health information"
    )
