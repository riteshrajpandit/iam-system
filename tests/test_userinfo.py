import json
import datetime
from django.test import TestCase, Client as TestClient
from django.urls import reverse
from oidc.models import RSAKey
from django.contrib.auth import get_user_model
from oidc.utils import generate_jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

User = get_user_model()

class UserInfoEndpointTest(TestCase):
    def setUp(self):
        self.client = TestClient()
        self.url = reverse('userinfo')
        
        # Create User
        self.user = User.objects.create_user(
            email='test@example.com', 
            password='password123',
            first_name='John',
            last_name='Doe'
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
            kid='test-key-1',
            private_key=self.private_pem,
            public_key=self.public_pem,
            is_active=True
        )

    def test_successful_userinfo(self):
        """Test valid token returns user info"""
        payload = {
            'iss': 'http://localhost:8000',
            'sub': str(self.user.id),
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            'scope': 'openid email profile'
        }
        token = generate_jwt(payload, key_id=self.rsa_key.kid)
        
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        
        self.assertEqual(response.status_code, 200)
        json_resp = response.json()
        
        self.assertEqual(json_resp['sub'], str(self.user.id))
        self.assertEqual(json_resp['email'], 'test@example.com')
        self.assertEqual(json_resp['given_name'], 'John')
        self.assertEqual(json_resp['family_name'], 'Doe')

    def test_missing_scopes(self):
        """Test missing optional scopes only returns sub"""
        payload = {
            'iss': 'http://localhost:8000',
            'sub': str(self.user.id),
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            'scope': 'openid' # No email or profile
        }
        token = generate_jwt(payload, key_id=self.rsa_key.kid)
        
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        
        self.assertEqual(response.status_code, 200)
        json_resp = response.json()
        self.assertEqual(json_resp['sub'], str(self.user.id))
        self.assertNotIn('email', json_resp)
        self.assertNotIn('name', json_resp)

    def test_missing_openid_scope(self):
        """Test missing openid scope returns Forbidden"""
        payload = {
            'iss': 'http://localhost:8000',
            'sub': str(self.user.id),
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            'scope': 'email profile' # Missing openid
        }
        token = generate_jwt(payload, key_id=self.rsa_key.kid)
        
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        
        self.assertEqual(response.status_code, 403)

    def test_expired_token(self):
        """Test expired token returns 401"""
        payload = {
            'iss': 'http://localhost:8000',
            'sub': str(self.user.id),
            'iat': datetime.datetime.utcnow() - datetime.timedelta(hours=2),
            'exp': datetime.datetime.utcnow() - datetime.timedelta(hours=1), # Expired
            'scope': 'openid'
        }
        token = generate_jwt(payload, key_id=self.rsa_key.kid)
        
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['error'], 'invalid_token')

    def test_invalid_signature(self):
        """Test token signed with unknown key returns 401"""
        # Create a new key that isn't in DB (or just different pair)
        other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # Manually sign with this other key
        import jwt # local import
        payload = {'sub': str(self.user.id), 'scope': 'openid'}
        
        # We need to manually sign this because generate_jwt uses DB keys
        token = jwt.encode(
            payload, 
            other_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ), 
            algorithm='RS256', 
            headers={'kid': 'test-key-1'} # Pretend to be the valid key
        )
        
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        
        self.assertEqual(response.status_code, 401)
