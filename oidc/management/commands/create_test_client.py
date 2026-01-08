from django.core.management.base import BaseCommand
from django.utils.crypto import get_random_string
from oidc.models import Client

class Command(BaseCommand):
    help = 'Create a test OIDC client application'

    def handle(self, *args, **options):
        # Generate a secure random secret
        plain_secret = get_random_string(length=32)
        
        # Create the client
        client = Client(
            name="Test App",
            redirect_uris=["http://localhost:3000/callback"],
            website_url="http://localhost:3000"
        )
        client.set_secret(plain_secret) # This hashes and saves the client
        
        self.stdout.write(self.style.SUCCESS('Successfully created test client'))
        self.stdout.write(f"Client Name: {client.name}")
        self.stdout.write(f"Client ID: {client.id}")
        self.stdout.write(f"Client Secret (Keep this safe!): {plain_secret}")
        self.stdout.write(f"Redirect URIs: {client.redirect_uris}")
