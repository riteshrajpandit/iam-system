import os
import sys
import django
import json
from urllib.parse import urlparse, parse_qs

# Setup Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django.test import Client as TestClient
from django.contrib.auth import get_user_model
from django.core.cache import cache
from oidc.models import Client, UserConsent

def test_auth_code_generation():
    print("Running Authorization Code Generation Tests...")
    
    c = TestClient()
    base_url = '/o/authorize/'
    User = get_user_model()
    
    # 1. Setup Data
    client = Client.objects.first()
    if not client:
        print("FAILURE: No client found.")
        sys.exit(1)
        
    user_email = "code_test@example.com"
    user_pass = "pass123"
    
    user, created = User.objects.get_or_create(email=user_email)
    if created:
        user.set_password(user_pass)
        user.save()

    # Pre-create Consent to skip consent screen
    UserConsent.objects.update_or_create(
        user=user, 
        client=client, 
        defaults={'granted_scopes': ['openid', 'email', 'profile']}
    )

    state = "random_state_val"
    nonce = "random_nonce_val"
    params = {
        'client_id': str(client.id),
        'redirect_uri': client.redirect_uris[0],
        'response_type': 'code',
        'code_challenge': 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        'code_challenge_method': 'S256',
        'state': state,
        'nonce': nonce
    }

    # Step 1: Login
    print("Step 1: Logging in user...")
    c.login(email=user_email, password=user_pass)

    # Step 2: Access Authorize (Expect Redirect with Code)
    print("Step 2: Accessing /authorize (Expect Redirect with Code)")
    resp = c.get(base_url, params)
    
    if resp.status_code == 302:
        print("SUCCESS: Redirected (302).")
        location = resp.get('Location')
        print(f"Location: {location}")
        
        # Parse URL
        parsed = urlparse(location)
        # Check base redirect URI
        if not parsed.geturl().startswith(client.redirect_uris[0]):
             print(f"FAILURE: Redirect URI Mismatch. Expected startswith {client.redirect_uris[0]}")
             sys.exit(1)
             
        qs = parse_qs(parsed.query)
        
        if 'code' not in qs:
            print("FAILURE: 'code' param missing in redirect.")
            sys.exit(1)
            
        code = qs['code'][0]
        print(f"Auth Code: {code}")
        
        if 'state' not in qs or qs['state'][0] != state:
            print("FAILURE: 'state' param missing or incorrect.")
            sys.exit(1)
            
        # Step 3: Verify Redis
        print("Step 3: verifying Redis storage...")
        cached_data_str = cache.get(f"oauth_code:{code}")
        
        if not cached_data_str:
             print("FAILURE: Code not found in Redis.")
             sys.exit(1)
             
        cached_data = json.loads(cached_data_str)
        
        if cached_data['client_id'] != str(client.id):
             print("FAILURE: Mismatched client_id in cache.")
             sys.exit(1)
        
        if cached_data['user_id'] != str(user.id):
             print(f"FAILURE: Mismatched user_id. Got {cached_data['user_id']}, Expected {user.id}")
             sys.exit(1)

        print("SUCCESS: Redis data verified.")
        print(cached_data)

    else:
        print(f"FAILURE: Expected 302, got {resp.status_code}")
        print(resp.content)
        sys.exit(1)

if __name__ == "__main__":
    test_auth_code_generation()
