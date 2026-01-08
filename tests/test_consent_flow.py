import os
import sys
import django

# Setup Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django.test import Client as TestClient
from django.contrib.auth import get_user_model
from oidc.models import Client, UserConsent

def test_consent_flow():
    print("Running Consent Flow Tests...")
    
    c = TestClient()
    base_url = '/o/authorize/'
    User = get_user_model()
    
    # 1. Setup Data
    client = Client.objects.first()
    if not client:
        print("FAILURE: No client found.")
        sys.exit(1)
        
    user_email = "consent_test@example.com"
    user_pass = "pass123"
    
    user, created = User.objects.get_or_create(email=user_email)
    if created:
        user.set_password(user_pass)
        user.save()

    # Ensure no previous consent
    UserConsent.objects.filter(user=user, client=client).delete()

    params = {
        'client_id': str(client.id),
        'redirect_uri': client.redirect_uris[0],
        'response_type': 'code',
        'code_challenge': 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        'code_challenge_method': 'S256'
    }

    # Step 1: Login
    print("Step 1: Logging in user...")
    c.login(email=user_email, password=user_pass)

    # Step 2: Access Authorize (Expect Consent Form)
    print("Step 2: Accessing /authorize (Expect Consent Form)")
    resp = c.get(base_url, params)
    
    if resp.status_code == 200:
        content = str(resp.content)
        if "Consent Required" in content and "Allow" in content:
            print("SUCCESS: Consent form rendered.")
        else:
            print("FAILURE: Consent form not rendered.")
            if "Consent Granted" in content:
                print("Error: Already granted?")
            else:
                print(f"Content snippet: {content[:200]}")
            sys.exit(1)
    else:
        print(f"FAILURE: Expected 200, got {resp.status_code}")
        sys.exit(1)

    # Step 3: Grant Consent
    print("Step 3: Clicking Allow")
    post_data = params.copy()
    post_data['allow'] = 'true'
    
    resp = c.post(base_url, post_data, follow=True)
    
    # Step 4: Verify Success
    if resp.status_code == 200:
        content = str(resp.content)
        if "Consent Granted. Next step: Generate Code" in content:
            print("SUCCESS: Consent granted and redirected correctly.")
        else:
            print(f"FAILURE: Expected success message. Got: {content[:200]}")
            sys.exit(1)
            
        # Verify DB
        if UserConsent.objects.filter(user=user, client=client).exists():
             print("SUCCESS: Consent record created in DB.")
        else:
             print("FAILURE: Consent record NOT found in DB.")
             sys.exit(1)
    else:
        print(f"FAILURE: Post-consent redirect failed. Code: {resp.status_code}")
        sys.exit(1)

if __name__ == "__main__":
    test_consent_flow()
