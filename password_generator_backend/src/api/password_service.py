import secrets
import string
from typing import List
from src.api.models import PasswordGenerationRequest, PasswordGenerationResponse


class PasswordGenerationService:
    """Service class for generating secure random passwords."""
    
    # Character sets for password generation
    UPPERCASE_CHARS = string.ascii_uppercase
    LOWERCASE_CHARS = string.ascii_lowercase
    NUMBER_CHARS = string.digits
    SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # PUBLIC_INTERFACE
    @staticmethod
    def generate_password(request: PasswordGenerationRequest) -> PasswordGenerationResponse:
        """
        Generate a secure random password based on the provided criteria.
        
        Args:
            request: PasswordGenerationRequest containing the generation criteria
            
        Returns:
            PasswordGenerationResponse containing the generated password and options used
            
        Raises:
            ValueError: If no character types are selected
        """
        # Validate that at least one character type is selected
        request.validate_at_least_one_option()
        
        # Build the character pool based on selected options
        char_pool = PasswordGenerationService._build_character_pool(request)
        
        # Ensure at least one character from each selected type is included
        password_chars = PasswordGenerationService._ensure_character_diversity(
            request, char_pool
        )
        
        # Fill remaining length with random characters from the pool
        remaining_length = request.length - len(password_chars)
        if remaining_length > 0:
            password_chars.extend(
                secrets.choice(char_pool) for _ in range(remaining_length)
            )
        
        # Shuffle to avoid predictable patterns
        # Using secrets.SystemRandom for cryptographically strong shuffling
        rng = secrets.SystemRandom()
        rng.shuffle(password_chars)
        
        # Join characters to form the final password
        generated_password = ''.join(password_chars)
        
        # Build response with password and options used
        return PasswordGenerationResponse(
            password=generated_password,
            length=len(generated_password),
            options_used={
                "include_uppercase": request.include_uppercase,
                "include_lowercase": request.include_lowercase,
                "include_numbers": request.include_numbers,
                "include_special": request.include_special
            }
        )
    
    @staticmethod
    def _build_character_pool(request: PasswordGenerationRequest) -> str:
        """
        Build the pool of characters to use for password generation.
        
        Args:
            request: PasswordGenerationRequest containing character type selections
            
        Returns:
            String containing all allowed characters for password generation
        """
        char_pool = ""
        
        if request.include_uppercase:
            char_pool += PasswordGenerationService.UPPERCASE_CHARS
        if request.include_lowercase:
            char_pool += PasswordGenerationService.LOWERCASE_CHARS
        if request.include_numbers:
            char_pool += PasswordGenerationService.NUMBER_CHARS
        if request.include_special:
            char_pool += PasswordGenerationService.SPECIAL_CHARS
            
        return char_pool
    
    @staticmethod
    def _ensure_character_diversity(
        request: PasswordGenerationRequest,
        char_pool: str
    ) -> List[str]:
        """
        Ensure at least one character from each selected type is included.
        
        Args:
            request: PasswordGenerationRequest containing character type selections
            char_pool: String containing all allowed characters
            
        Returns:
            List of characters ensuring diversity
        """
        password_chars = []
        
        # Add at least one character from each selected type
        if request.include_uppercase:
            password_chars.append(
                secrets.choice(PasswordGenerationService.UPPERCASE_CHARS)
            )
        if request.include_lowercase:
            password_chars.append(
                secrets.choice(PasswordGenerationService.LOWERCASE_CHARS)
            )
        if request.include_numbers:
            password_chars.append(
                secrets.choice(PasswordGenerationService.NUMBER_CHARS)
            )
        if request.include_special:
            password_chars.append(
                secrets.choice(PasswordGenerationService.SPECIAL_CHARS)
            )
            
        return password_chars
