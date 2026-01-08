from django.core.management.base import BaseCommand
from django.core.cache import cache
import time

class Command(BaseCommand):
    help = 'Verify Redis connection'

    def handle(self, *args, **options):
        self.stdout.write('Checking Redis connection...')
        
        try:
            # Set a value
            cache.set('test_key', 'working', timeout=30)
            
            # Get the value
            value = cache.get('test_key')
            
            if value == 'working':
                self.stdout.write(self.style.SUCCESS(f'Redis connection successful! Retrieved value: {value}'))
            else:
                self.stdout.write(self.style.ERROR(f'Redis connection failed. Expected "working", got "{value}"'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error connecting to Redis: {e}'))
