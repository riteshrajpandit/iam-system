from django.views import View
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse, HttpResponseForbidden
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.hashers import make_password
from .models import Client, UserConsent, Scope, RefreshToken, RSAKey
from .utils import validate_pkce, generate_jwt
from .authentication import JWTAuthentication
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ValidationError
from urllib.parse import urlencode
from django.utils.crypto import get_random_string
from django.core.cache import cache
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone
import datetime
import json
import base64
import uuid
import jwt
import hashlib

class AuthorizeView(View):
    def get(self, request):
        client_id = request.GET.get('client_id')
        redirect_uri = request.GET.get('redirect_uri')
        response_type = request.GET.get('response_type')
        code_challenge = request.GET.get('code_challenge')
        code_challenge_method = request.GET.get('code_challenge_method')
        state = request.GET.get('state')
        nonce = request.GET.get('nonce')

        if not client_id:
            return HttpResponseBadRequest("Missing client_id")
        
        try:
            client = Client.objects.get(id=client_id)
        except (Client.DoesNotExist, ValidationError):
            return HttpResponseBadRequest("Invalid client_id")

        if not redirect_uri or redirect_uri not in client.redirect_uris:
            return HttpResponseBadRequest("Invalid redirect_uri")

        if response_type != 'code':
            return HttpResponseBadRequest("Unsupported response_type. Must be 'code'")

        if not code_challenge:
             return HttpResponseBadRequest("Missing code_challenge (PKCE required)")
        
        if code_challenge_method != 'S256':
             return HttpResponseBadRequest("Unsupported code_challenge_method. Must be 'S256'")

        # 2. Authentication Check
        if request.user.is_authenticated:
            # 2a. Check Consent
            # For this iteration, we assume default scopes (openid, profile, email) are requested
            # In a real OIDC impl, we parse request.GET.get('scope').
            required_scope_names = ['openid', 'profile', 'email']
            
            try:
                consent = UserConsent.objects.get(user=request.user, client=client)
                
                # Check if all required scopes are present in granted_scopes
                has_all_scopes = all(s in consent.granted_scopes for s in required_scope_names)
                
                if has_all_scopes:
                    # Generate Auth Code
                    code = get_random_string(length=32)
                    
                    data = {
                        "client_id": str(client.id),
                        "user_id": str(request.user.id),
                        "scope": consent.granted_scopes,
                        "code_challenge": code_challenge,
                        "code_challenge_method": code_challenge_method,
                        "redirect_uri": redirect_uri,
                        "nonce": nonce or ''
                    }
                    
                    cache.set(f"oauth_code:{code}", json.dumps(data), timeout=60)
                    
                    response_params = {'code': code}
                    if state:
                        response_params['state'] = state
                        
                    return redirect(f"{redirect_uri}?{urlencode(response_params)}")

            except UserConsent.DoesNotExist:
                pass
            
            # 2b. Render Consent Page
            # Fetch scope objects to display details
            scopes = client.allowed_scopes.filter(name__in=required_scope_names)
            
            context = {
                'client': client,
                'scopes': scopes,
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': response_type,
                'code_challenge': code_challenge,
                'code_challenge_method': code_challenge_method
            }
            return render(request, 'oidc/consent.html', context)
        
        # 3. Render Login Page (with preserved params)
        context = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': response_type,
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method
        }
        return render(request, 'oidc/login.html', context)

    def post(self, request):
        # Extract params from hidden fields
        client_id = request.POST.get('client_id')
        redirect_uri = request.POST.get('redirect_uri')
        response_type = request.POST.get('response_type')
        code_challenge = request.POST.get('code_challenge')
        code_challenge_method = request.POST.get('code_challenge_method')

        # Check for Consent Action
        if 'allow' in request.POST or 'deny' in request.POST:
             # Ensure user is authenticated for consent action
             if not request.user.is_authenticated:
                 return redirect(f"{request.path}?{request.META['QUERY_STRING']}")

             if 'deny' in request.POST:
                 # Redirect with error
                 error_params = {'error': 'access_denied', 'error_description': 'User denied consent'}
                 return redirect(f"{redirect_uri}?{urlencode(error_params)}")
             
             if 'allow' in request.POST:
                 try:
                    client = Client.objects.get(id=client_id)
                    # Grant default scopes
                    scopes = ['openid', 'profile', 'email']
                    
                    UserConsent.objects.update_or_create(
                        user=request.user,
                        client=client,
                        defaults={'granted_scopes': scopes}
                    )
                    
                    # Redirect back to self (GET) to process success
                    params = {
                        'client_id': client_id,
                        'redirect_uri': redirect_uri,
                        'response_type': response_type,
                        'code_challenge': code_challenge,
                        'code_challenge_method': code_challenge_method
                    }
                    return redirect(f"{request.path}?{urlencode(params)}")

                 except Client.DoesNotExist:
                     return HttpResponseBadRequest("Invalid client")

        # Credentials (Login Flow)
        email = request.POST.get('email')
        password = request.POST.get('password')

        if email and password:
            user = authenticate(request, email=email, password=password)

            if user is not None:
                login(request, user)
                
                # Reconstruct URL to redirect back to GET logic (which will now see user is authenticated)
                params = {
                    'client_id': client_id,
                    'redirect_uri': redirect_uri,
                    'response_type': response_type,
                    'code_challenge': code_challenge,
                    'code_challenge_method': code_challenge_method
                }
                # Redirect to self (GET)
                return redirect(f"{request.path}?{urlencode(params)}")
            else:
                # Login Failed
                context = {
                    'error': "Invalid email or password",
                    'client_id': client_id,
                    'redirect_uri': redirect_uri,
                    'response_type': response_type,
                    'code_challenge': code_challenge,
                    'code_challenge_method': code_challenge_method
                }
                return render(request, 'oidc/login.html', context)
        
        return HttpResponseBadRequest("Invalid Request")

@method_decorator(csrf_exempt, name='dispatch')
class TokenView(View):
    def post(self, request):
        grant_type = request.POST.get('grant_type')
        code = request.POST.get('code')
        redirect_uri = request.POST.get('redirect_uri')
        client_id = request.POST.get('client_id')
        client_secret = request.POST.get('client_secret')
        code_verifier = request.POST.get('code_verifier')

        # Check for Basic Auth
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Basic '):
            try:
                encoded_credentials = auth_header.split(' ')[1]
                decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
                if ':' in decoded_credentials:
                    basic_id, basic_secret = decoded_credentials.split(':', 1)
                    if client_id and client_id != basic_id:
                         return JsonResponse({'error': 'invalid_client', 'error_description': 'Client ID mismatch'}, status=400)
                    client_id = basic_id
                    client_secret = basic_secret
            except Exception:
                return JsonResponse({'error': 'invalid_client'}, status=401)

        if grant_type == 'authorization_code':
            if not code or not redirect_uri or not code_verifier:
                return JsonResponse({'error': 'invalid_request', 'error_description': 'Missing required parameters'}, status=400)

            # Redis Validation
            key = f"oauth_code:{code}"
            data = cache.get(key)
        
            if not data:
                return JsonResponse({'error': 'invalid_grant', 'error_description': 'Invalid or expired code'}, status=400)
            
            try:
                if isinstance(data, str):
                    data = json.loads(data)
            except Exception:
                 return JsonResponse({'error': 'server_error', 'error_description': 'Cache data error'}, status=500)
        
            if data.get('client_id') != str(client_id):
                return JsonResponse({'error': 'invalid_grant', 'error_description': 'Client mismatch'}, status=400)
            
            if data.get('redirect_uri') != redirect_uri:
                return JsonResponse({'error': 'invalid_grant', 'error_description': 'Redirect URI mismatch'}, status=400)

            # PKCE Validation
            challenge = data.get('code_challenge')
            method = data.get('code_challenge_method', 'S256')
        
            if not challenge:
                 return JsonResponse({'error': 'invalid_grant'}, status=400)

            if not validate_pkce(code_verifier, challenge, method):
                return JsonResponse({'error': 'invalid_grant', 'error_description': 'PKCE validation failed'}, status=400)

            # Fetch Client
            try:
                client = Client.objects.get(id=client_id)
            except Client.DoesNotExist:
                return JsonResponse({'error': 'invalid_client', 'error_description': 'Client not found'}, status=400)

            # Validation Success - Invalidate Code
            cache.delete(key)
            
            user_id = data.get('user_id')
            scope = data.get('scope', 'openid')
            nonce = data.get('nonce')

        elif grant_type == 'refresh_token':
            refresh_token = request.POST.get('refresh_token')
            if not refresh_token:
                 return JsonResponse({'error': 'invalid_request', 'error_description': 'Missing refresh_token'}, status=400)
            
            token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
            try:
                rt = RefreshToken.objects.get(token_hash=token_hash)
            except RefreshToken.DoesNotExist:
                return JsonResponse({'error': 'invalid_grant', 'error_description': 'Invalid refresh token'}, status=400)
            
            if not rt.is_valid():
                return JsonResponse({'error': 'invalid_grant', 'error_description': 'IdP Refresh Token expired or revoked'}, status=400)
            
            if str(rt.client.id) != str(client_id):
                 return JsonResponse({'error': 'invalid_grant', 'error_description': 'Client mismatch'}, status=400)
            
            client = rt.client
            user_id = str(rt.user.id)
            # Retain original scopes or handle scope shrinking (optional) - for now use defaults or fetch from prev context if stored
            # Ideally scope is stored in RefreshToken, but model doesn't have it. We'll default to 'openid' or whatever.
            # But the user schema didn't include scope in RefreshToken table.
            scope = 'openid' 
            nonce = None # No nonce in refresh flow usually
            
            # Optional: Revoke old refresh token? Rotate?
            # For this task, we can correct the request: "Step 5: Try to use...".
            
        else:
            return JsonResponse({'error': 'unsupported_grant_type'}, status=400)

        # Token Minting
        
        # Calculate expiry times
        now = timezone.now()
        access_token_exp = now + datetime.timedelta(hours=1)
        
        # Base claims
        common_claims = {
            'iss': 'http://localhost:8000',
            'sub': user_id,
            'aud': str(client_id),
            'iat': int(now.timestamp()),
            'exp': int(access_token_exp.timestamp()),
        }

        # Mint Access Token
        access_token_payload = common_claims.copy()
        access_token_payload['scope'] = scope
        access_token = generate_jwt(access_token_payload)

        # Mint ID Token
        id_token_payload = common_claims.copy()
        if nonce:
            id_token_payload['nonce'] = nonce
        id_token = generate_jwt(id_token_payload)

        # Generate Refresh Token
        refresh_token_str = get_random_string(64)
        refresh_token_exp = now + datetime.timedelta(days=30)
        
        # Check if we should rotate the refresh token
        # If grant_type was refresh_token, maybe revoke the old one?
        # Standard OIDC: Rotation is recommended.
        if grant_type == 'refresh_token':
            # Revoke the used one
            rt_used = RefreshToken.objects.get(token_hash=hashlib.sha256(request.POST.get('refresh_token').encode()).hexdigest())
            rt_used.is_revoked = True
            rt_used.save()

        # Create user object for FK if needed, but we have user_id
        # Need actual User instance for RefreshToken FK
        User = get_user_model()
        user_obj = User.objects.get(id=user_id)

        RefreshToken.objects.create(
            user=user_obj,
            client=client,
            token_hash=hashlib.sha256(refresh_token_str.encode()).hexdigest(),
            expires_at=refresh_token_exp
        )

        return JsonResponse({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'id_token': id_token,
            'refresh_token': refresh_token_str,
            'scope': scope
        })

@method_decorator(csrf_exempt, name='dispatch')
class RevocationView(View):
    def post(self, request):
        token = request.POST.get('token')
        token_type_hint = request.POST.get('token_type_hint')
        
        # We only really care about RefreshTokens in DB. 
        # Access tokens are JWTs (stateless), so we can't revoke them without blacklist (out of scope for now).
        # OR if we had a blacklist table.
        # Requirement: "Identify if the token is a Refresh Token. Find ... by hashing ... Set is_revoked = True."
        
        if token:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            RefreshToken.objects.filter(token_hash=token_hash).update(is_revoked=True)
            
        return HttpResponse(status=200)

@method_decorator(csrf_exempt, name='dispatch')
class IntrospectionView(View):
    def post(self, request):
        # 1. Basic Auth Validation
        auth_header = request.headers.get('Authorization')
        client_id = None
        
        if auth_header and auth_header.startswith('Basic '):
            try:
                encoded_credentials = auth_header.split(' ')[1]
                decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
                if ':' in decoded_credentials:
                    client_id, client_secret = decoded_credentials.split(':', 1)
                    
                    try:
                        client = Client.objects.get(id=client_id)
                        if not client.check_secret(client_secret):
                             return JsonResponse({'error': 'invalid_client'}, status=401)
                    except (Client.DoesNotExist, ValidationError):
                        return JsonResponse({'error': 'invalid_client'}, status=401)
            except Exception:
                return JsonResponse({'error': 'invalid_client'}, status=401)
        else:
             # Try body
             client_id = request.POST.get('client_id')
             client_secret = request.POST.get('client_secret')
             if client_id and client_secret:
                 try:
                    client = Client.objects.get(id=client_id)
                    if not client.check_secret(client_secret):
                         return JsonResponse({'error': 'invalid_client'}, status=401)
                 except (Client.DoesNotExist, ValidationError):
                    return JsonResponse({'error': 'invalid_client'}, status=401)
             else:
                 return JsonResponse({'error': 'invalid_client'}, status=401)

        token = request.POST.get('token')
        if not token:
             return JsonResponse({'active': False})

        # Check if it's a Refresh Token
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        try:
            rt = RefreshToken.objects.get(token_hash=token_hash)
            if rt.is_valid():
                return JsonResponse({
                    'active': True,
                    'scope': 'openid', # Default or stored
                    'client_id': str(rt.client.id),
                    'sub': str(rt.user.id),
                    'token_type': 'refresh_token'
                })
        except RefreshToken.DoesNotExist:
            pass
            
        # Check if it's an Access Token (JWT verify)
        try:
            # We need to find the kid to get key
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get('kid')
            
            if kid:
                key = RSAKey.objects.filter(kid=kid).first()
                if key:
                    payload = jwt.decode(token, key.public_key, algorithms=['RS256'], options={'verify_aud': False})
                    # Use audience from payload to match client_id request? RFC doesn't strictly force it for introspection if authenticated
                    return JsonResponse({
                        'active': True,
                        'scope': payload.get('scope'),
                        'client_id': payload.get('aud'),
                        'sub': payload.get('sub'),
                        'exp': payload.get('exp'),
                        'token_type': 'access_token'
                    })
        except Exception:
            pass # Invalid JWT

        return JsonResponse({'active': False})

@method_decorator(csrf_exempt, name='dispatch')
class UserInfoView(View):
    def get(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'invalid_token', 'error_description': 'Missing or invalid Authorization header'}, status=401)
        
        token = auth_header.split(' ')[1]
        
        try:
            # 1. Get header to find kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get('kid')
            
            if not kid:
                 return JsonResponse({'error': 'invalid_token'}, status=401)
            
            # 2. Fetch Public Key
            try:
                rsa_key = RSAKey.objects.get(kid=kid)
            except RSAKey.DoesNotExist:
                return JsonResponse({'error': 'invalid_token', 'error_description': 'Unknown key identifier'}, status=401)
                
            # 3. Decode & Verify
            # We skip audience verification because the access token aud is the client_id, 
            # but this endpoint (the IdP) is implicitly the audience for UserInfo access.
            payload = jwt.decode(
                token, 
                rsa_key.public_key, 
                algorithms=['RS256'],
                options={'verify_aud': False} 
            )
            
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'invalid_token', 'error_description': 'Token expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'invalid_token'}, status=401)
            
        # 4. Check Scope
        scope_data = payload.get('scope')
        if isinstance(scope_data, str):
            scopes = scope_data.split()
        elif isinstance(scope_data, list):
            scopes = scope_data
        else:
            scopes = []

        if 'openid' not in scopes:
             return HttpResponseForbidden("Missing openid scope")
             
        # 5. Get User
        user_id = payload.get('sub')
        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return JsonResponse({'error': 'invalid_token'}, status=401)
            
        # 6. Build Response
        response_data = {
            'sub': str(user.id),
        }
        
        if 'email' in scopes:
            response_data['email'] = user.email
            response_data['email_verified'] = True # Assuming validated for now
            
        if 'profile' in scopes:
            response_data['name'] = f"{user.first_name} {user.last_name}".strip()
            response_data['given_name'] = user.first_name
            response_data['family_name'] = user.last_name
            
        return JsonResponse(response_data)

class ProtectedTestView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return JsonResponse({
            "message": "You are in!", 
            "user": request.user.email
        })




class LogoutView(View):
    def get(self, request):
        logout(request)
        redirect_uri = request.GET.get('post_logout_redirect_uri')
        if redirect_uri:
            return redirect(redirect_uri)
        return HttpResponse("Logged out successfully.")
