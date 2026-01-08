import json
from django.core.management.base import BaseCommand
from oidc.models import Client

class Command(BaseCommand):
    help = 'Generates a Postman collection for the IOXET IAM APIs'

    def handle(self, *args, **options):
        # 1. Fetch a client for variables
        client = Client.objects.first()
        client_id = str(client.id) if client else "PLACEHOLDER_CLIENT_ID"
        client_secret = "PLACEHOLDER_SECRET" # Secrets are hashed
        
        # 2. Define Variables
        variables = [
            {"key": "base_url", "value": "http://localhost:8000", "type": "string"},
            {"key": "client_id", "value": client_id, "type": "string"},
            {"key": "client_secret", "value": client_secret, "type": "string"},
            {"key": "access_token", "value": "", "type": "string"},
            {"key": "code_verifier", "value": "a"*43, "type": "string"}
        ]

        # 3. Construct Collection structure
        collection = {
            "info": {
                "name": "IOXET IAM API",
                "description": "Auto-generated collection for OIDC Identity Provider",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "variable": variables,
            "item": []
        }

        # 4. Add Items (Endpoints)
        
        # Register
        collection['item'].append({
            "name": "Register User",
            "request": {
                "method": "POST",
                "header": [
                    {"key": "Content-Type", "value": "application/json"}
                ],
                "body": {
                    "mode": "raw",
                    "raw": json.dumps({
                        "email": "newuser@example.com",
                        "password": "strongpassword123",
                        "first_name": "Test",
                        "last_name": "User"
                    }, indent=4)
                },
                "url": {
                    "raw": "{{base_url}}/api/v1/auth/register/",
                    "host": ["{{base_url}}"],
                    "path": ["api", "v1", "auth", "register", ""]
                }
            }
        })

        # Authorize (Browser)
        collection['item'].append({
            "name": "Authorize (Browser Step)",
            "request": {
                "method": "GET",
                "header": [],
                "url": {
                    "raw": "{{base_url}}/o/authorize/?response_type=code&client_id={{client_id}}&redirect_uri=http://localhost:8000/callback&scope=openid email profile&code_challenge=E9Melhoa2O9udQQXRFRZFIOT1o1bTS1qlt-icwYivUI&code_challenge_method=S256",
                    "host": ["{{base_url}}"],
                    "path": ["o", "authorize", ""],
                    "query": [
                        {"key": "response_type", "value": "code"},
                        {"key": "client_id", "value": "{{client_id}}"},
                        {"key": "redirect_uri", "value": "http://localhost:8000/callback"},
                        {"key": "scope", "value": "openid email profile"},
                        {"key": "code_challenge", "value": "E9Melhoa2O9udQQXRFRZFIOT1o1bTS1qlt-icwYivUI", "description": "S256 of 'a'*43"},
                        {"key": "code_challenge_method", "value": "S256"}
                    ]
                },
                "description": "Copy this URL to a browser to log in and get the 'code'."
            }
        })

        # Token Exchange
        collection['item'].append({
            "name": "Token Exchange",
            "request": {
                "method": "POST",
                "header": [
                     {"key": "Content-Type", "value": "application/x-www-form-urlencoded"}
                ],
                "body": {
                    "mode": "urlencoded",
                    "urlencoded": [
                        {"key": "grant_type", "value": "authorization_code", "type": "text"},
                        {"key": "code", "value": "PASTE_CODE_HERE", "type": "text"},
                        {"key": "client_id", "value": "{{client_id}}", "type": "text"},
                        {"key": "client_secret", "value": "{{client_secret}}", "type": "text"},
                        {"key": "redirect_uri", "value": "http://localhost:8000/callback", "type": "text"},
                        {"key": "code_verifier", "value": "{{code_verifier}}", "type": "text"}
                    ]
                },
                "url": {
                    "raw": "{{base_url}}/o/token/",
                    "host": ["{{base_url}}"],
                    "path": ["o", "token", ""]
                }
            }
        })

        # UserInfo
        collection['item'].append({
            "name": "UserInfo",
            "request": {
                "method": "GET",
                "header": [
                    {"key": "Authorization", "value": "Bearer {{access_token}}"}
                ],
                "url": {
                    "raw": "{{base_url}}/o/userinfo/",
                    "host": ["{{base_url}}"],
                    "path": ["o", "userinfo", ""]
                }
            }
        })

        # Introspect
        collection['item'].append({
            "name": "Introspect Token",
            "request": {
                "method": "POST",
                "header": [
                    {"key": "Content-Type", "value": "application/x-www-form-urlencoded"}
                ],
                "auth": {
                    "type": "basic",
                    "basic": [
                        {"key": "password", "value": "{{client_secret}}", "type": "string"},
                        {"key": "username", "value": "{{client_id}}", "type": "string"}
                    ]
                },
                "body": {
                    "mode": "urlencoded",
                    "urlencoded": [
                        {"key": "token", "value": "{{access_token}}", "type": "text"}
                    ]
                },
                "url": {
                    "raw": "{{base_url}}/o/introspect/",
                    "host": ["{{base_url}}"],
                    "path": ["o", "introspect", ""]
                }
            }
        })

        # Revoke
        collection['item'].append({
            "name": "Revoke Token",
            "request": {
                "method": "POST",
                "header": [
                    {"key": "Content-Type", "value": "application/x-www-form-urlencoded"}
                ],
                 "auth": {
                    "type": "basic",
                    "basic": [
                        {"key": "password", "value": "{{client_secret}}", "type": "string"},
                        {"key": "username", "value": "{{client_id}}", "type": "string"}
                    ]
                },
                "body": {
                    "mode": "urlencoded",
                    "urlencoded": [
                        {"key": "token", "value": "REFRESH_TOKEN_HERE", "type": "text"},
                        {"key": "token_type_hint", "value": "refresh_token", "type": "text"}
                    ]
                },
                "url": {
                    "raw": "{{base_url}}/o/revoke/",
                    "host": ["{{base_url}}"],
                    "path": ["o", "revoke", ""]
                }
            }
        })

        # Write to file
        with open('postman_collection.json', 'w') as f:
            json.dump(collection, f, indent=4)
        
        self.stdout.write(self.style.SUCCESS('Successfully generated postman_collection.json'))
