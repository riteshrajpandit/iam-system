import json
import datetime
import jwt
from django.test import TestCase, Client as TestClient
from django.urls import reverse
from oidc.models import RSAKey
from django.contrib.auth import get_user_model
from oidc.utils import generate_jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

User = get_user_model()

class JwtMiddlewareTest(TestCase):
    def setUp(self):
        self.client = TestClient()
        self.url = reverse('test-auth')
        
        # Create User
        self.user = User.objects.create_user(
            email='middleware@example.com', 
            password='password123'
        )
        
        # Create RSA Key for signing
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
            kid='test-key-mw',
            private_key=self.private_pem,
            public_key=self.public_pem,
            is_active=True
        )

    def test_successful_auth(self):
        """Test valid token grants access"""
        payload = {
            'iss': 'http://localhost:8000',
            'sub': str(self.user.id),
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            'scope': 'openid email'
        }
        token = generate_jwt(payload, key_id=self.rsa_key.kid)
        
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['message'], "You are in!")
        self.assertEqual(response.json()['user'], self.user.email)

    def test_no_token(self):
        """Test missing token returns 401/403"""
        response = self.client.get(self.url)
        # DRF returns 401 or 403 depending on auth class configs, usually 401 for no credentials
        self.assertIn(response.status_code, [401, 403])

    def test_tampered_token(self):
        """Test signature mismatch returns 401/403"""
        payload = {
            'iss': 'http://localhost:8000',
            'sub': str(self.user.id),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        # Sign with a different key not present in DB (or just generate one on fly)
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pem = other_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        token = jwt.encode(
            payload, 
            other_pem, 
            algorithm='RS256', 
            headers={'kid': self.rsa_key.kid} # Claim to be the valid key
        )
        
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        
        self.assertIn(response.status_code, [401, 403])

    def test_expired_token(self):
        """Test expired token returns 401/403"""
        payload = {
            'iss': 'http://localhost:8000',
            'sub': str(self.user.id),
            'iat': datetime.datetime.utcnow() - datetime.timedelta(hours=2),
            'exp': datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        }
        token = generate_jwt(payload, key_id=self.rsa_key.kid)
        
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        
        self.assertIn(response.status_code, [401, 403])

    def test_unknown_key_id(self):
        """Test token with unknown kid returns 401/403"""
        payload = {'sub': str(self.user.id), 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
        token = jwt.encode(
             payload, 
             self.private_pem, 
             algorithm='RS256', 
             headers={'kid': 'unknown-kid'}
        )
        
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertIn(response.status_code, [401, 403])
