import jwt
from django.contrib.auth import get_user_model
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed
from .models import RSAKey

User = get_user_model()

class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]

        try:
            # 1. Get header to find kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get('kid')
            
            if not kid:
                raise AuthenticationFailed('Invalid token header: Missing kid')

            # 2. Fetch Public Key
            try:
                rsa_key = RSAKey.objects.get(kid=kid)
            except RSAKey.DoesNotExist:
                raise AuthenticationFailed('Invalid token: Unknown key identifier')

            # 3. Decode & Verify
            # We skip audience verification for this internal check, or we could verify it matches client_id if we had context
            # For general API protection, verifying signature and expiry is the main goal.
            payload = jwt.decode(
                token,
                rsa_key.public_key,
                algorithms=['RS256'],
                options={'verify_aud': False} 
            )

            # 4. Get User
            user_id = payload.get('sub')
            if not user_id:
                raise AuthenticationFailed('Invalid token: Missing subject')

            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                raise AuthenticationFailed('User not found')

            if not user.is_active:
                raise AuthenticationFailed('User is inactive')

            return (user, token)

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token expired')
        except jwt.InvalidTokenError as e:
            raise AuthenticationFailed(f'Invalid token: {str(e)}')
