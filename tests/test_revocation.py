import json
import hashlib
import datetime
import base64
from django.test import TestCase, Client as TestClient
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils import timezone
from oidc.models import Client, RefreshToken, RSAKey
from django.contrib.auth import get_user_model
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

User = get_user_model()

class RevocationIntrospectionTest(TestCase):
    def setUp(self):
        self.client = TestClient()
        self.revoke_url = reverse('revoke')
        self.introspect_url = reverse('introspect')
        self.token_url = reverse('token')
        
        # RSA Key (Required for minting new tokens)
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
            kid='test-key-revoc',
            private_key=self.private_pem,
            public_key=self.public_pem,
            is_active=True
        )

        # User & Client
        self.user = User.objects.create_user(email='revoker@example.com', password='password123')
        self.oidc_client = Client.objects.create(
            name='Test Client',
            redirect_uris=['http://localhost:8000/callback'],
            website_url='http://localhost:8000'
        )
        self.client_secret = 'secret123'
        self.oidc_client.set_secret(self.client_secret)
        self.oidc_client.save()
        
        # Create a valid Refresh Token
        self.refresh_token_str = get_random_string(64)
        expires_at = timezone.now() + datetime.timedelta(days=30)
        self.rt = RefreshToken.objects.create(
            user=self.user,
            client=self.oidc_client,
            token_hash=hashlib.sha256(self.refresh_token_str.encode()).hexdigest(),
            expires_at=expires_at,
            is_revoked=False
        )
        
        # Auth Header for Introspection
        credentials = f"{self.oidc_client.id}:{self.client_secret}"
        self.basic_auth = f"Basic {base64.b64encode(credentials.encode()).decode()}"

    def test_introspection_active_token(self):
        """Introspection should return active=True for valid refresh token"""
        response = self.client.post(
            self.introspect_url,
            {'token': self.refresh_token_str},
            HTTP_AUTHORIZATION=self.basic_auth
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['active'])
        self.assertEqual(response.json()['sub'], str(self.user.id))

    def test_revocation_flow(self):
        """Revoke token and check introspection"""
        # 1. Revoke
        response = self.client.post(
            self.revoke_url,
            {'token': self.refresh_token_str}
        )
        self.assertEqual(response.status_code, 200)
        
        # Verify DB update
        self.rt.refresh_from_db()
        self.assertTrue(self.rt.is_revoked)
        
        # 2. Introspect (should be inactive)
        response = self.client.post(
            self.introspect_url,
            {'token': self.refresh_token_str},
            HTTP_AUTHORIZATION=self.basic_auth
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()['active'])

    def test_refresh_grant_with_revoked_token(self):
        """Try to use revoked refresh token to get new tokens"""
        # Revoke first
        self.rt.is_revoked = True
        self.rt.save()
        
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token_str,
            'client_id': self.oidc_client.id,
            'client_secret': self.client_secret
        }
        
        response = self.client.post(self.token_url, data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_refresh_grant_success_and_rotation(self):
        """Test successful refresh and token rotation"""
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token_str,
            'client_id': self.oidc_client.id,
            'client_secret': self.client_secret
        }
        
        response = self.client.post(self.token_url, data)
        self.assertEqual(response.status_code, 200)
        json_resp = response.json()
        
        self.assertIn('access_token', json_resp)
        new_refresh_token = json_resp['refresh_token']
        self.assertNotEqual(new_refresh_token, self.refresh_token_str)
        
        # Verify old token is revoked (rotation)
        self.rt.refresh_from_db()
        self.assertTrue(self.rt.is_revoked)
        
        # Verify new token is valid
        new_hash = hashlib.sha256(new_refresh_token.encode()).hexdigest()
        self.assertTrue(RefreshToken.objects.filter(token_hash=new_hash, is_revoked=False).exists())
