import os
import sys
import django
from datetime import timedelta

# Setup Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django.utils import timezone
from django.contrib.auth import get_user_model
from oidc.models import Client, RefreshToken

def test_refresh_token_model():
    print("Running RefreshToken model tests...")
    
    User = get_user_model()
    
    # 1. Fetch Client and User
    try:
        client = Client.objects.first()
        if not client:
            print("FAILURE: No client found. Run 'python manage.py create_test_client' first.")
            return

        user = User.objects.filter(email='testuser@example.com').first()
        if not user:
            print("FAILURE: User 'testuser@example.com' not found. Run Task 2 registration first.")
            return
            
    except Exception as e:
        print(f"FAILURE: Database error: {e}")
        return

    # 2. Create RefreshToken instance
    raw_token = "secret_refresh_token_12345"
    expires_at = timezone.now() + timedelta(days=30)
    
    rt = RefreshToken(
        user=user,
        client=client,
        expires_at=expires_at
    )
    
    # 3. Set Token (Hashing)
    rt.set_token(raw_token)
    print(f"Token hashed and saved. Hash: {rt.token_hash[:20]}...")

    # 4. Assertions
    
    # Assert hash is not plain text
    if rt.token_hash == raw_token:
        print("FAILURE: Token stored in plain text!")
        sys.exit(1)
    else:
        print("SUCCESS: Token is hashed.")

    # Assert check_token (Positive)
    if rt.check_token(raw_token):
        print("SUCCESS: check_token returned True for correct token.")
    else:
        print("FAILURE: check_token returned False for correct token.")
        sys.exit(1)

    # Assert check_token (Negative)
    if not rt.check_token("wrong_token"):
        print("SUCCESS: check_token returned False for wrong token.")
    else:
        print("FAILURE: check_token returned True for wrong token!")
        sys.exit(1)

    # Assert is_valid
    if rt.is_valid():
         print("SUCCESS: is_valid returned True for fresh token.")
    else:
         print("FAILURE: is_valid returned False for fresh token.")
         sys.exit(1)

    # Test revocation
    rt.is_revoked = True
    rt.save()
    if not rt.is_valid():
        print("SUCCESS: is_valid returned False after revocation.")
    else:
        print("FAILURE: is_valid returned True after revocation!")
        sys.exit(1)

if __name__ == "__main__":
    test_refresh_token_model()
