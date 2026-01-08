import base64
import hashlib
import json
from django.test import TestCase, Client as TestClient
from django.urls import reverse
from django.core.cache import cache
from oidc.models import Client
from django.contrib.auth import get_user_model

User = get_user_model()

class TokenExchangeValidationTest(TestCase):
    def setUp(self):
        self.client = TestClient()
        self.url = reverse('token')
        
        # Create a user
        self.user = User.objects.create_user(email='test@example.com', password='password123')
        
        # Create an OIDC Client
        self.oidc_client = Client.objects.create(
            name='Test Client',
            redirect_uris=['http://localhost:8000/callback'],
            website_url='http://localhost:8000'
        )
        self.client_secret = 'secret123'
        self.oidc_client.set_secret(self.client_secret)
        self.oidc_client.save()
        
        # PKCE Setup
        self.code_verifier = "a" * 43 # Minimum length 43
        # S256 Challenge generation logic
        digest = hashlib.sha256(self.code_verifier.encode('ascii')).digest()
        encoded = base64.urlsafe_b64encode(digest).decode('ascii')
        self.code_challenge = encoded.rstrip('=')
        
        # Seed Redis with a valid code
        self.auth_code = "valid-auth-code"
        self.redis_key = f"oauth_code:{self.auth_code}"
        self.redis_data = {
            'client_id': str(self.oidc_client.id),
            'user_id': str(self.user.id),
            'scope': 'openid email',
            'redirect_uri': 'http://localhost:8000/callback',
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256',
            'nonce': 'test-nonce'
        }
        cache.set(self.redis_key, self.redis_data, timeout=300)

    def tearDown(self):
        cache.delete(self.redis_key)
    
    def test_missing_parameters(self):
        """Test missing required parameters returns 400"""
        data = {
            'grant_type': 'authorization_code',
            # Missing code, client_id, etc.
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_request')

    def test_invalid_grant_type(self):
        """Test invalid grant_type returns 400"""
        data = {
            'grant_type': 'password', # Unsupported
            'code': self.auth_code,
            'client_id': self.oidc_client.id,
            'client_secret': self.client_secret,
            'redirect_uri': 'http://localhost:8000/callback',
            'code_verifier': self.code_verifier
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'unsupported_grant_type')

    def test_invalid_client_authentication(self):
        """Test wrong client secret returns 401"""
        data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'client_id': self.oidc_client.id,
            'client_secret': 'wrong-secret',
            'redirect_uri': 'http://localhost:8000/callback',
            'code_verifier': self.code_verifier
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['error'], 'invalid_client')

    def test_invalid_auth_code(self):
        """Test non-existent or expired code returns 400"""
        data = {
            'grant_type': 'authorization_code',
            'code': 'invalid-code',
            'client_id': self.oidc_client.id,
            'client_secret': self.client_secret,
            'redirect_uri': 'http://localhost:8000/callback',
            'code_verifier': self.code_verifier
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_pkce_validation_failure(self):
        """Test wrong code_verifier returns 400"""
        # Ensure redis has the code
        cache.set(self.redis_key, self.redis_data, timeout=300)
        
        data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'client_id': self.oidc_client.id,
            'client_secret': self.client_secret,
            'redirect_uri': 'http://localhost:8000/callback',
            'code_verifier': 'wrong-verifier'
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_redirect_uri_mismatch(self):
        """Test redirect_uri mismatch returns 400"""
        cache.set(self.redis_key, self.redis_data, timeout=300)
        
        data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'client_id': self.oidc_client.id,
            'client_secret': self.client_secret,
            'redirect_uri': 'http://not-allowed.com',
            'code_verifier': self.code_verifier
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_successful_token_exchange(self):
        """Test valid request returns 200 and mocked tokens"""
        # Ensure redis has the code
        cache.set(self.redis_key, self.redis_data, timeout=300)

        data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'client_id': self.oidc_client.id,
            'client_secret': self.client_secret,
            'redirect_uri': 'http://localhost:8000/callback',
            'code_verifier': self.code_verifier
        }
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, 200)
        json_resp = response.json()
        self.assertIn('access_token', json_resp)
        self.assertEqual(json_resp['token_type'], 'Bearer')
        
        # Verify code is deleted from Redis (replay protection)
        self.assertIsNone(cache.get(self.redis_key))

    def test_basic_auth_header(self):
        """Test client authentication via Basic Auth header"""
        cache.set(self.redis_key, self.redis_data, timeout=300)
        
        credentials = f"{self.oidc_client.id}:{self.client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            # No client_id/secret in body
            'redirect_uri': 'http://localhost:8000/callback',
            'code_verifier': self.code_verifier
        }
        
        # HTTP_AUTHORIZATION is how Django sees Authorization header
        response = self.client.post(
            self.url, 
            data, 
            HTTP_AUTHORIZATION=f'Basic {encoded_credentials}'
        )

        self.assertEqual(response.status_code, 200)

