import hashlib
import base64
import jwt
from .models import RSAKey

def validate_pkce(code_verifier, code_challenge, method='S256'):
    """
    Validates the PKCE code verifier against the code challenge.
    Supports 'S256' (default) and 'plain' methods.
    """
    if method == 'plain':
        return code_verifier == code_challenge
    
    if method == 'S256':
        # 1. SHA256 hash of the ASCII bytes of the verifier
        digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
        
        # 2. Base64-URL encode the digest
        encoded = base64.urlsafe_b64encode(digest).decode('ascii')
        
        # 3. Strip trailing padding '=' as per OIDC/PKCE spec
        calculated_challenge = encoded.rstrip('=')
        
        return calculated_challenge == code_challenge
    
    return False

def generate_jwt(payload, key_id=None):
    """
    Generates an RS256 signed JWT using the active RSAKey.
    """
    if key_id:
        key = RSAKey.objects.filter(kid=key_id, is_active=True).first()
    else:
        key = RSAKey.objects.filter(is_active=True).first()
    
    if not key:
        raise Exception("No active RSA key found")
    
    # jwt.encode returns a string in PyJWT >= 2.0.0
    token = jwt.encode(
        payload, 
        key.private_key, 
        algorithm='RS256', 
        headers={'kid': key.kid}
    )
    return token

