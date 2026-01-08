import uuid
import hashlib
from django.db import models
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password

class Scope(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name

class Client(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    allowed_scopes = models.ManyToManyField(Scope, related_name='clients', blank=True)
    client_secret_hash = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    redirect_uris = models.JSONField(default=list, help_text="List of allowed redirect URIs")
    website_url = models.URLField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def set_secret(self, raw_secret):
        self.client_secret_hash = make_password(raw_secret)
        self.save()

    def check_secret(self, raw_secret):
        return check_password(raw_secret, self.client_secret_hash)

    def __str__(self):
        return self.name

class UserConsent(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='consents')
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='consents')
    granted_scopes = models.JSONField(default=list)
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'client'], name='unique_user_client_consent')
        ]

    def __str__(self):
        return f"{self.user} -> {self.client}"

class RefreshToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='refresh_tokens')
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='refresh_tokens')
    token_hash = models.CharField(max_length=255)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_revoked = models.BooleanField(default=False)

    def set_token(self, raw_token):
        # Use SHA256 for deterministic hashing to allow lookup
        self.token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        self.save()

    def check_token(self, raw_token):
        return self.token_hash == hashlib.sha256(raw_token.encode()).hexdigest()

    def is_valid(self):
        from django.utils import timezone
        return not self.is_revoked and self.expires_at > timezone.now()

    def __str__(self):
        return f"RefreshToken({self.user}, {self.client})"

class RSAKey(models.Model):
    kid = models.CharField(max_length=50, unique=True)
    private_key = models.TextField(help_text="PEM format")
    public_key = models.TextField(help_text="PEM format")
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"RSAKey(kid={self.kid})"




