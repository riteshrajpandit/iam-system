# IOXET IAM System - Implementation & Integration Documentation

**Version:** 1.0.0  
**Status:** Local Development / Preview  
**Base URL:** `http://localhost:8000`

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Architecture](#2-system-architecture)
3. [Quick Start (Local Environment)](#3-quick-start-local-environment)
4. [Client Registration & Configuration](#4-client-registration--configuration)
5. [Authentication Flows (SDK Reference)](#5-authentication-flows-sdk-reference)
    - [Step 1: Terminology & Prerequisites](#step-1-terminology--prerequisites)
    - [Step 2: Generating PKCE Challenges](#step-2-generating-pkce-challenges)
    - [Step 3: Redirecting to Authorization Server](#step-3-redirecting-to-authorization-server)
    - [Step 4: Handling the Callback & Token Exchange](#step-4-handling-the-callback--token-exchange)
6. [API Reference](#6-api-reference)
    - [Authorization Endpoint](#authorization-endpoint)
    - [Token Endpoint](#token-endpoint)
    - [User Info Endpoint](#user-info-endpoint)
    - [Revocation Endpoint](#revocation-endpoint)
    - [Logout Endpoint](#logout-endpoint)
    - [Introspection Endpoint](#introspection-endpoint)
    - [User Registration Endpoint](#user-registration-endpoint)
7. [Security & Compliance](#7-security--compliance)
    - [CORS Configuration](#cors-configuration)
    - [Token Storage Best Practices](#token-storage-best-practices)

---

## 1. Introduction

The IOXET IAM (Identity and Access Management) System is a robust, standards-compliant OAuth 2.0 and OpenID Connect (OIDC) provider. It allows third-party applications ("Clients") to authenticate users securely without handling passwords directly. 

This system implements the **Authorization Code Flow with PKCE (Proof Key for Code Exchange)**, which is the industry standard for securing public clients like Single Page Applications (SPAs) and Mobile Apps.

---

## 2. System Architecture

The ecosystem consists of three main entities:

1.  **Authorization Server (IOXET IAM)**: 
    -   *URL:* `http://localhost:8000`
    -   *Role:* Authenticates users, issues Access and Refresh tokens.
2.  **Client Application (Third-Party App)**:
    -   *Example:* `http://localhost:3000`
    -   *Role:* Redirects users to IAM, handles callbacks, maintains user sessions.
3.  **Resource Owner (User)**:
    -   The end-user who authorizes the Client to access their data.

### Sequence Diagram (High Level)

1.  **User** clicks "Login" on **Client**.
2.  **Client** generates PKCE `code_verifier` and `code_challenge`.
3.  **Client** redirects **User** to **IAM Authorization Endpoint** with `code_challenge`.
4.  **User** logs in at **IAM** (if not already logged in).
5.  **User** consents to scopes (`openid`, `profile`, `email`).
6.  **IAM** redirects **User** back to **Client Redirect URI** with an `code`.
7.  **Client** sends `code` + `code_verifier` (the secret) to **IAM Token Endpoint**.
8.  **IAM** validates the verifier against the challenge.
9.  **IAM** responds with `access_token` and `refresh_token`.
10. **Client** uses `access_token` to fetch profile from **User Info Endpoint**.

---

## 3. Quick Start (Local Environment)

To run the IAM system locally for testing integration:

1.  **Prerequisites**: Python 3.10+, pip, virtualenv.
2.  **Installation**:
    ```bash
    git clone https://github.com/ioxet/iam-system.git
    cd iam-system
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
3.  **Database Setup**:
    ```bash
    python manage.py migrate
    ```
4.  **Run Server**:
    ```bash
    python manage.py runserver 8000
    ```
    The IAM Provider is now live at `http://localhost:8000`.

---

## 4. Client Registration & Configuration

Before your application can communicate with IOXET IAM, it must be registered as a **Client**.

### Creating a Client
*Currently handled via the Django Admin Panel or Database seeding.*

**Required Fields:**
-   **Client ID**: A unique UUID (e.g., `00000000-0000-0000-0000-000000000001`).
-   **Client Secret**: (Optional for Public Clients using PKCE, but recommended to be empty for SPAs).
-   **Redirect URIs**: Whitelisted Return URLs. Crucial for security.
    -   *Example:* `http://localhost:3000/auth/callback`
-   **Allowed Scopes**: `openid`, `email`, `profile`.

### CORS Configuration
If your application runs in a browser (SPA) and calls the Token Endpoint directly (not via a backend proxy), your domain **must** be added to the IAM `CORS_ALLOWED_ORIGINS` setting.

*For Local Development:*
Ensure `http://localhost:8000` allows `http://localhost:3000`.

---

## 5. Authentication Flows (SDK Reference)

To integrate "Login with IOXET", follow this implementation guide. This logic mirrors the `lib/auth.ts` found in our demo frontend.

### Step 1: Terminology & Prerequisites
You need:
-   `CLIENT_ID`
-   `IAM_URL` (`http://localhost:8000`)
-   `REDIRECT_URI` (Must match what is registered in IAM)

### Step 2: Generating PKCE Challenges
PKCE prevents code injection attacks. You must generate a random `code_verifier` and hashed `code_challenge`.

**JavaScript/TypeScript Example:**
```typescript
// 1. Generate a random string (43-128 chars)
function generateRandomString(length: number) {
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const values = crypto.getRandomValues(new Uint8Array(length));
    return values.reduce((acc, x) => acc + possible[x % possible.length], "");
}

// 2. Hash it with SHA-256
async function sha256(plain: string) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return window.crypto.subtle.digest('SHA-256', data);
}

// 3. Base64URL Encode
function base64UrlEncode(arrayBuffer: ArrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

// Usage
const codeVerifier = generateRandomString(128);
const challengeHash = await sha256(codeVerifier);
const codeChallenge = base64UrlEncode(challengeHash);

// SAVE VERIFIER FOR LATER!
sessionStorage.setItem('pkce_code_verifier', codeVerifier);
```

### Step 3: Redirecting to Authorization Server
Construct the URL and redirect the user's browser.

**Endpoint:** `GET /o/authorize/`

**Parameters:**
| Parameter | Value | Description |
|-----------|-------|-------------|
| `response_type` | `code` | Required. |
| `client_id` | `<YOUR_CLIENT_ID>` | Required. |
| `redirect_uri` | `<YOUR_REDIRECT_URI>` | Required. Must match registration. |
| `scope` | `openid email profile` | Space separated permissions. |
| `state` | `<random_string>` | Recommended. Prevent CSRF. |
| `code_challenge` | `<generated_challenge>` | Required (PKCE). |
| `code_challenge_method` | `S256` | Required. |

**Example URL Construction:**
```typescript
const params = new URLSearchParams({
    response_type: 'code',
    client_id: '...',
    redirect_uri: 'http://localhost:3000/auth/callback',
    scope: 'openid email profile',
    code_challenge: '...',
    code_challenge_method: 'S256',
    state: 'xyz123'
});
window.location.href = `http://localhost:8000/o/authorize/?${params.toString()}`;
```

### Step 4: Handling the Callback & Token Exchange
The user will be redirected back to your `redirect_uri` with a `code` parameter.

**URL received:** `http://localhost:3000/auth/callback?code=AUTH_CODE_HERE&state=xyz123`

Exchange this code for tokens using a `POST` request.

**Endpoint:** `POST /o/token/`

**Payload (Form URL Encoded):**
-   `grant_type`: `authorization_code`
-   `client_id`: `<YOUR_CLIENT_ID>`
-   `code`: `<The code from query params>`
-   `redirect_uri`: `<YOUR_REDIRECT_URI>` (Must match the one used in Step 3 exactly)
-   `code_verifier`: `<The string saved in session storage in Step 2>`

**Response:**
```json
{
    "access_token": "eyJhbG...",
    "expires_in": 36000,
    "token_type": "Bearer",
    "scope": "openid email profile",
    "refresh_token": "def502...",
    "id_token": "eyJra..."
}
```

---

## 6. API Reference

### Authorization Endpoint
Used to initiate the sign-in flow.
-   **URL**: `/o/authorize/`
-   **Method**: `GET`

### Token Endpoint
Used to exchange authorization codes or refresh tokens for access tokens.
-   **URL**: `/o/token/`
-   **Method**: `POST`
-   **Content-Type**: `application/x-www-form-urlencoded`

**Refreshing Tokens:**
To refresh an expired access token:
```bash
curl -X POST http://localhost:8000/o/token/ \
     -d "grant_type=refresh_token" \
     -d "client_id=<ID>" \
     -d "refresh_token=<REFRESH_TOKEN>"
```

### User Info Endpoint
Retrieve the profile of the authenticated user.
-   **URL**: `/o/userinfo/`
-   **Method**: `GET`
-   **Headers**: `Authorization: Bearer <ACCESS_TOKEN>`

**Response Example:**
```json
{
    "sub": "user_uuid",
    "email": "user@example.com",
    "name": "John Doe",
    "given_name": "John",
    "family_name": "Doe"
}
```

### Revocation Endpoint
Invalidate a refresh token (e.g., on logout).
-   **URL**: `/o/revoke/`
-   **Method**: `POST`
-   **Params**: `token`, `token_type_hint=refresh_token`

### Logout Endpoint
Terminates the server-side session at the Identity Provider.
-   **URL**: `/o/logout/`
-   **Method**: `GET`
-   **Params**: `post_logout_redirect_uri` (URL to return to after logout)
-   **Usage**: Redirect the user's browser to this URL to force a re-login next time.

### Introspection Endpoint
(For Resource Servers) Check if a token is active.
-   **URL**: `/o/introspect/`
-   **Method**: `POST`

### User Registration Endpoint
Register a new user programmatically.
-   **URL**: `/api/v1/auth/register/`
-   **Method**: `POST`
-   **Content-Type**: `application/json`
-   **Payload**:
    ```json
    {
        "email": "newuser@example.com",
        "password": "SecurePassword123!",
        "first_name": "Jane",
        "last_name": "Doe"
    }
    ```

---

## 7. Security & Compliance

### CORS Configuration
Cross-Origin Resource Sharing (CORS) is a security feature that restricts web browsers from making requests to a different domain than the one that served the web page.

If you see an error: `Access to fetch ... has been blocked by CORS policy`, it means your Client Domain is not authorized by IOXET IAM.

**Solution:**
1.  Identify your origin (e.g., `https://myapp.com` or `http://localhost:8080`).
2.  Add this origin to the `CORS_ALLOWED_ORIGINS` list in the IAM `settings.py`.
3.  Restart the IAM server.

### Token Storage Best Practices

**Do NOT store tokens in LocalStorage.**
Storing Access/Refresh tokens in `localStorage` or `sessionStorage` makes them accessible to any JavaScript code running on your page (XSS attacks).

**Recommended Approach (BFF Pattern):**
1.  **Frontend** (Next.js/React) sends the Auth Code to **Your Backend** (API Routes).
2.  **Your Backend** exchanges the code for tokens with **IAM**.
3.  **Your Backend** stores the tokens in **HttpOnly, Secure Cookies**.
4.  Cookies are automatically sent with requests to your backend, which then proxies the request to IAM with the Bearer Token.

This is the architecture implemented in the IOXET Demo App (`frontend/app/api/auth/exchange`).

---

**© 2026 IOXET IAM Systems**
