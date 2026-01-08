import os
import sys
import django

# Setup Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django.test import Client as TestClient
from django.contrib.auth import get_user_model
from oidc.models import Client

def test_login_flow():
    print("Running Login Flow Tests...")
    
    c = TestClient()
    base_url = '/o/authorize/'
    User = get_user_model()
    
    # 1. Setup Data
    client = Client.objects.first()
    if not client:
        print("FAILURE: No client found.")
        sys.exit(1)
        
    test_email = "login_test@example.com"
    test_password = "password123"
    
    if not User.objects.filter(email=test_email).exists():
        User.objects.create_user(email=test_email, password=test_password)
        print(f"Created test user: {test_email}")

    params = {
        'client_id': str(client.id),
        'redirect_uri': client.redirect_uris[0],
        'response_type': 'code',
        'code_challenge': 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        'code_challenge_method': 'S256'
    }

    # Step 1: GET /authorize (Anonymous)
    print("Step 1: GET /authorize (Anonymous)")
    resp = c.get(base_url, params)
    
    if resp.status_code == 200:
        if 'Sign In' in str(resp.content):
            print("SUCCESS: Login page rendered.")
        else:
            print("FAILURE: Login page did not render correctly.")
            print(resp.content)
            sys.exit(1)
    else:
        print(f"FAILURE: Expected 200, got {resp.status_code}")
        sys.exit(1)

    # Step 2: POST credentials
    print("Step 2: POST credentials")
    # Add credentials to params
    post_data = params.copy()
    post_data['email'] = test_email
    post_data['password'] = test_password
    
    resp = c.post(base_url, post_data, follow=True) # follow=True follows the redirect
    
    # Step 3: Check Result
    print("Step 3: Checking Redirect and Authenticated State")
    
    # After login, we redirect back to the same URL, which hits GET, 
    # checks is_authenticated, and validates params again.
    
    if resp.status_code == 200:
        content = str(resp.content)
        if "User is logged in. Next step: Consent" in content:
            print("SUCCESS: User authenticated and redirected correctly.")
        else:
            print("FAILURE: Did not see success message.")
            if "Sign In" in content:
                print("Error: Still on login page (Auth failed?)")
            elif "Validation Successful" in content:
                 print("Error: Saw old message?")
            else:
                 print(f"Content: {content}")
            sys.exit(1)
    else:
        print(f"FAILURE: Final response was {resp.status_code}")
        sys.exit(1)

if __name__ == "__main__":
    test_login_flow()
