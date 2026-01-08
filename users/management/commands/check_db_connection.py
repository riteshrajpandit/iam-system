from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import connections
from django.db.utils import OperationalError

class Command(BaseCommand):
    help = 'Verify database connection by counting users'

    def handle(self, *args, **options):
        self.stdout.write('Checking database connection...')
        
        try:
            db_conn = connections['default']
            try:
                c = db_conn.cursor()
            except OperationalError:
                self.stdout.write(self.style.ERROR('Database unavailable'))
                return

            User = get_user_model()
            user_count = User.objects.count()
            self.stdout.write(self.style.SUCCESS(f'Database connection successful! Current user count: {user_count}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error connecting to database: {e}'))
