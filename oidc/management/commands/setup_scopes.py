from django.core.management.base import BaseCommand
from oidc.models import Scope, Client

class Command(BaseCommand):
    help = 'Setup default OIDC scopes and assign to Test App'

    def handle(self, *args, **options):
        # Define default scopes
        default_scopes = [
            ('openid', 'OpenID Connect scope'),
            ('profile', 'Access to user profile details'),
            ('email', 'Access to user email address'),
        ]

        created_scopes = []
        for name, desc in default_scopes:
            scope, created = Scope.objects.get_or_create(
                name=name,
                defaults={'description': desc}
            )
            created_scopes.append(scope)
            if created:
                self.stdout.write(self.style.SUCCESS(f'Created scope: {name}'))
            else:
                self.stdout.write(f'Scope already exists: {name}')

        # Assign to Test App
        try:
            client = Client.objects.get(name="Test App")
            client.allowed_scopes.add(*created_scopes)
            self.stdout.write(self.style.SUCCESS(f'Added scopes to client "{client.name}"'))
            self.stdout.write(f'Allowed Scopes: {[s.name for s in client.allowed_scopes.all()]}')
        except Client.DoesNotExist:
            self.stdout.write(self.style.WARNING('Client "Test App" not found. Run create_test_client first.'))
