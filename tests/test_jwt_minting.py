import base64
import hashlib
import json
import jwt
import datetime
from django.test import TestCase, Client as TestClient
from django.urls import reverse
from django.core.cache import cache
from oidc.models import Client, RSAKey, RefreshToken
from django.contrib.auth import get_user_model
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

User = get_user_model()

class TopkenJwtMintingTest(TestCase):
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
        
        # Create RSA Key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        self.public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        self.rsa_key = RSAKey.objects.create(
            kid='test-key-1',
            private_key=self.private_pem,
            public_key=self.public_pem,
            is_active=True
        )

        # PKCE Setup
        self.code_verifier = "a" * 43 
        digest = hashlib.sha256(self.code_verifier.encode('ascii')).digest()
        encoded = base64.urlsafe_b64encode(digest).decode('ascii')
        self.code_challenge = encoded.rstrip('=')
        
        # Seed Redis
        self.auth_code = "valid-auth-code"
        self.redis_key = f"oauth_code:{self.auth_code}"
        self.nonce_val = "test-nonce-123"
        self.redis_data = {
            'client_id': str(self.oidc_client.id),
            'user_id': str(self.user.id),
            'scope': 'openid email',
            'redirect_uri': 'http://localhost:8000/callback',
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256',
            'nonce': self.nonce_val
        }
        cache.set(self.redis_key, self.redis_data, timeout=300)

    def tearDown(self):
        cache.delete(self.redis_key)
        
    def test_jwt_minting_and_claims(self):
        """Test that tokens are minted with correct signature and claims"""
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
        access_token = json_resp['access_token']
        id_token = json_resp['id_token']
        refresh_token_str = json_resp['refresh_token']
        
        # Verify Token Fields
        self.assertEqual(json_resp['token_type'], 'Bearer')
        self.assertEqual(json_resp['expires_in'], 3600)
        
        # Verify ID Token Signature & Claims
        decoded_id = jwt.decode(id_token, self.public_pem, algorithms=['RS256'], audience=str(self.oidc_client.id))
        
        self.assertEqual(decoded_id['iss'], 'http://localhost:8000')
        self.assertEqual(decoded_id['sub'], str(self.user.id))
        self.assertEqual(decoded_id['aud'], str(self.oidc_client.id))
        self.assertEqual(decoded_id['nonce'], self.nonce_val)
        
        # Verify Access Token Signature & Claims
        decoded_at = jwt.decode(access_token, self.public_pem, algorithms=['RS256'], audience=str(self.oidc_client.id))
        self.assertEqual(decoded_at['iss'], 'http://localhost:8000')
        self.assertIn('openid email', decoded_at['scope'])

        # Verify Refresh Token in DB
        rt = RefreshToken.objects.filter(user=self.user, client=self.oidc_client).first()
        self.assertIsNotNone(rt)
        self.assertTrue(rt.check_token(refresh_token_str))
        self.assertFalse(rt.is_revoked)
