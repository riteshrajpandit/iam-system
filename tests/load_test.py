import requests
import concurrent.futures
import time
import base64
import hashlib
import random
import string
import json
from urllib.parse import urlparse, parse_qs

# Configuration
BASE_URL = "http://localhost:8000"
NUM_USERS = 50
MAX_WORKERS = 10
CLIENT_ID = "00000000-0000-0000-0000-000000000001" 
CLIENT_SECRET = "secret123"

def log_debug(debug, message):
    if debug:
        print(f"[DEBUG] {message}", flush=True)

def simulate_user(index, debug=False):
    session = requests.Session()
    email = f"load_user_{index}_{int(time.time())}@example.com"
    password = "password123!"
    
    log_debug(debug, f"User {index} starting flow. Email: {email}")

    try:
        # 1. Register
        reg_url = f"{BASE_URL}/api/v1/auth/register/"
        reg_data = {
            "email": email,
            "password": password,
            "first_name": f"LoadUser{index}",
            "last_name": "Test"
        }
        log_debug(debug, f"1. Registering at {reg_url}")
        resp = session.post(reg_url, json=reg_data, timeout=10)
        
        if resp.status_code != 201:
            log_debug(debug, f"Registration failed body: {resp.text}")
            return False, f"Register Failed: {resp.status_code}"
        log_debug(debug, "   -> Registered.")

        # 2. Start Auth (Get CSRF)
        code_verifier = ''.join(random.choices(string.ascii_letters + string.digits, k=50))
        digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')

        auth_params = {
            'response_type': 'code',
            'client_id': CLIENT_ID,
            'redirect_uri': 'http://localhost:8000/callback',
            'scope': 'openid email profile',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        auth_url = f"{BASE_URL}/o/authorize/"
        log_debug(debug, f"2. Initial Auth Request to {auth_url}")
        resp = session.get(auth_url, params=auth_params, timeout=10)
        
        if resp.status_code != 200:
             return False, f"Auth Init Failed: {resp.status_code}"
             
        csrf_token = session.cookies.get('csrftoken')
        if not csrf_token:
            return False, "No CSRF Token"
        log_debug(debug, "   -> Got CSRF Token.")

        # 3. Login
        # IMPORTANT: We must pass back the auth parameters (client_id, etc) as hidden fields
        # because the view expects them in POST to preserve state.
        login_data = {
            'email': email,
            'password': password,
            'csrfmiddlewaretoken': csrf_token
        }
        # Merge the auth params since the view expects them as hidden fields
        login_data.update(auth_params)

        headers = {'Referer': resp.url}
        log_debug(debug, f"3. Logging in at {resp.url}")
        
        # Note: resp.url is the same authorize URL (with params). 
        # The View handles both GET (render form) and POST (process login).
        resp = session.post(resp.url, data=login_data, headers=headers, timeout=10)
        
        if resp.status_code != 200:
            log_debug(debug, f"Login Failed Body: {resp.text}")
            return False, f"Login Failed: {resp.status_code}"
        
        log_debug(debug, "   -> Login POST successful (or redirect followed).")
            
        # 4. Consent 
        # Check for commonly used strings in the consent template
        if "Consent Required" in resp.text or "access your account" in resp.text:
            log_debug(debug, "4. Consent Page Detected. Approving...")
            csrf_token = session.cookies.get('csrftoken')
            consent_data = {
                'allow': 'Allow',
                'csrfmiddlewaretoken': csrf_token
            }
            # Also need to pass hidden fields here
            consent_data.update(auth_params)
            
            resp = session.post(resp.url, data=consent_data, headers=headers, timeout=10)
            log_debug(debug, "   -> Consent Approved.")
        else:
             log_debug(debug, "4. No Consent Page (Maybe skipped or auto-approved).")
             # Extract title for debugging
             import re
             title_match = re.search('<title>(.*?)</title>', resp.text, re.IGNORECASE)
             page_title = title_match.group(1) if title_match else "No Title"
             log_debug(debug, f"   Actual Page Title: {page_title}")
             if "Invalid" in resp.text:
                 log_debug(debug, "   Found 'Invalid' in text.")
        
        # 5. Capture Code
        final_url = resp.url
        log_debug(debug, f"5. Final URL after redirects: {final_url}")
        
        parsed = urlparse(final_url)
        qs = parse_qs(parsed.query)
        
        if 'code' not in qs:
             # Check if error
             if 'error' in qs:
                 return False, f"Auth Error: {qs['error'][0]}"
             return False, f"No Code in URL: {final_url}"
             
        auth_code = qs['code'][0]
        log_debug(debug, f"   -> Captured Auth Code: {auth_code[:6]}...")
        
        # 6. Exchange Token
        token_url = f"{BASE_URL}/o/token/"
        token_data = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'redirect_uri': 'http://localhost:8000/callback',
            'code_verifier': code_verifier
        }
        
        log_debug(debug, f"6. Exchanging token at {token_url}")
        resp = session.post(token_url, data=token_data, timeout=10)
        if resp.status_code != 200:
             return False, f"Token Exchange Failed: {resp.text}"
             
        tokens = resp.json()
        access_token = tokens.get('access_token')
        
        if not access_token:
            return False, "No Access Token"
        log_debug(debug, "   -> Got Access Token.")

        # 7. Verify UserInfo
        info_url = f"{BASE_URL}/o/userinfo/"
        log_debug(debug, f"7. Fetching UserInfo at {info_url}")
        resp = session.get(info_url, headers={'Authorization': f"Bearer {access_token}"}, timeout=10)
        
        if resp.status_code != 200:
             log_debug(debug, f"UserInfo Failure Body: {resp.text}")
             return False, f"UserInfo Failed: {resp.status_code}"
             
        data = resp.json()
        if data.get('email') != email:
             return False, "UserInfo Email Mismatch"
             
        log_debug(debug, "   -> Flow Complete Success!")
        return True, "Success"

    except Exception as e:
        log_debug(debug, f"EXCEPTION: {str(e)}")
        return False, f"Exception: {str(e)}"

if __name__ == "__main__":
    print(f"Starting End-to-End Load Test with {NUM_USERS} users...", flush=True)
    print(f"Target: {BASE_URL}", flush=True)
    print(f"Client ID: {CLIENT_ID}", flush=True)
    
    # Run one user with debug FIRST to verify and show process
    print("\n--- Running Single User Debug Trace ---", flush=True)
    success, msg = simulate_user(0, debug=True)
    if not success:
        print(f"DEBUG RUN FAILED: {msg}", flush=True)
        print("Aborting full load test due to debug failure.", flush=True)
        exit(1)
    else:
        print("DEBUG RUN SUCCESS. Starting Load Test...", flush=True)

    success_count = 0
    fail_count = 0
    
    # We already ran user 0. Running 1 to NUM_USERS
    users_range = range(1, NUM_USERS)
    
    start_all = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(simulate_user, i, debug=False): i for i in users_range}
        
        for future in concurrent.futures.as_completed(futures):
            idx = futures[future]
            success, msg = future.result()
            
            if success:
                success_count += 1
                print(f"User {idx}: Success", flush=True)
            else:
                fail_count += 1
                print(f"User {idx}: Failed ({msg})", flush=True)
    
    # Add the debug user
    success_count += 1
                
    end_all = time.time()
    duration = end_all - start_all
    
    print("\n" + "="*30, flush=True)
    print("LOAD TEST COMPLETE", flush=True)
    print(f"Total Users: {NUM_USERS}", flush=True)
    print(f"Total Success: {success_count}/{NUM_USERS}", flush=True)
    print(f"Total Duration: {duration:.2f}s", flush=True)
    print("="*30, flush=True)
