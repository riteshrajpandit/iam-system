import sys
import os

# Add project root to path to allow imports
sys.path.append(os.getcwd())

from oidc.utils import validate_pkce

def test_pkce_validation():
    print("Running PKCE Validation Tests...")

    # Test Vector (S256)
    # Source: https://datatracker.ietf.org/doc/html/rfc7636#appendix-B
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    
    # Test valid S256
    if validate_pkce(verifier, expected_challenge, method='S256'):
        print("SUCCESS: Valid S256 challenge matched correctly.")
    else:
        print(f"FAILURE: Valid S256 challenge did NOT match.")
        print(f"Verifier: {verifier}")
        print(f"Expected: {expected_challenge}")
        sys.exit(1)

    # Test invalid S256
    if not validate_pkce("wrong_verifier", expected_challenge, method='S256'):
        print("SUCCESS: Invalid verifier correctly rejected.")
    else:
        print("FAILURE: Invalid verifier was ACCEPTED!")
        sys.exit(1)

    # Test plain
    plain_verifier = "plain_secret"
    if validate_pkce(plain_verifier, plain_verifier, method='plain'):
        print("SUCCESS: Valid plain challenge matched.")
    else:
        print("FAILURE: Valid plain challenge did NOT match.")
        sys.exit(1)

if __name__ == "__main__":
    test_pkce_validation()
