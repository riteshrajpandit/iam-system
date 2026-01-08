from django.core.management.base import BaseCommand
from django.utils.crypto import get_random_string
from oidc.models import RSAKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class Command(BaseCommand):
    help = 'Generate a new RSA key pair for OIDC JWT signing'

    def handle(self, *args, **options):
        # 1. Generate RSA Key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # 2. Serialize Private Key
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # 3. Serialize Public Key
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # 4. Generate KID
        kid = get_random_string(length=16)

        # 5. Save to DB
        rsa_key = RSAKey.objects.create(
            kid=kid,
            private_key=pem_private,
            public_key=pem_public,
            is_active=True
        )

        self.stdout.write(self.style.SUCCESS(f'Successfully generated RSA Key with kid: {rsa_key.kid}'))
