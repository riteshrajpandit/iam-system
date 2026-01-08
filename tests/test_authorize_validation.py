import os
import sys
import django

# Setup Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django.test import Client as TestClient
from oidc.models import Client

def test_authorize_validation():
    print("Running Authorize Endpoint Validation Tests...")
    
    c = TestClient()
    base_url = '/o/authorize/'
    
    # Get a valid client
    client = Client.objects.first()
    if not client:
        print("FAILURE: No client found. Run 'create_test_client' management command.")
        sys.exit(1)
        
    valid_redirect = client.redirect_uris[0]
    valid_client_id = str(client.id)
    
    # Test 1: Missing client_id
    resp = c.get(base_url)
    if resp.status_code == 400:
        print("SUCCESS: Rejected missing client_id")
    else:
        print(f"FAILURE: Expected 400 for missing client_id, got {resp.status_code}")

    # Test 2: Invalid redirect_uri
    resp = c.get(base_url, {
        'client_id': valid_client_id,
        'redirect_uri': 'http://evil.com/callback',
        'response_type': 'code',
        'code_challenge': 'xyz',
        'code_challenge_method': 'S256'
    })
    if resp.status_code == 400:
        print("SUCCESS: Rejected invalid redirect_uri")
    else:
        print(f"FAILURE: Expected 400 for invalid redirect_uri, got {resp.status_code}")

    # Test 3: Missing code_challenge
    resp = c.get(base_url, {
        'client_id': valid_client_id,
        'redirect_uri': valid_redirect,
        'response_type': 'code',
        # 'code_challenge': 'xyz', 
        'code_challenge_method': 'S256'
    })
    if resp.status_code == 400:
        print("SUCCESS: Rejected missing code_challenge")
    else:
        print(f"FAILURE: Expected 400 for missing code_challenge, got {resp.status_code}")
        
    # Test 4: Valid Request
    resp = c.get(base_url, {
        'client_id': valid_client_id,
        'redirect_uri': valid_redirect,
        'response_type': 'code',
        'code_challenge': 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        'code_challenge_method': 'S256'
    })
    if resp.status_code == 200:
        print("SUCCESS: Accepted valid request")
    else:
        print(f"FAILURE: Expected 200 for valid request, got {resp.status_code}")
        print(resp.content)

if __name__ == "__main__":
    test_authorize_validation()
