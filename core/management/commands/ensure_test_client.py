from django.core.management.base import BaseCommand
from oidc.models import Client
from django.contrib.auth import get_user_model
import uuid
import uuid


class Command(BaseCommand):
    help = 'Ensures a known client exists for load testing'

    def handle(self, *args, **options):
        # Known UUID for testing
        client_id = uuid.UUID('00000000-0000-0000-0000-000000000001')
        client_secret = 'secret123'
        
        client, created = Client.objects.get_or_create(
            id=client_id,
            defaults={
                'name': 'Load Test Client',
                'redirect_uris': ['http://localhost:8000/callback'],
                'website_url': 'http://localhost:8000'
            }
        )
        
        if created:
            client.set_secret(client_secret)
            client.save()
            self.stdout.write(self.style.SUCCESS(f'Created Load Test Client: {client_id}'))
        else:
            # Ensure secret is set (hash matches)
            if not client.check_secret(client_secret):
                client.set_secret(client_secret)
                client.save()
            self.stdout.write(self.style.SUCCESS(f'Load Test Client already exists: {client_id}'))
