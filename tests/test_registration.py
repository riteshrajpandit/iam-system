import requests
import sys

def test_registration():
    url = "http://localhost:8000/api/v1/auth/register/"
    data = {
        "email": "testuser@example.com",
        "password": "strongpassword123",
        "first_name": "Test",
        "last_name": "User"
    }
    
    try:
        response = requests.post(url, data=data)
        if response.status_code == 201:
            print("SUCCESS: User registration successful (201 Created)")
            print(response.json())
        else:
            print(f"FAILURE: Received status code {response.status_code}")
            print(response.text)
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("FAILURE: Could not connect to server. Is it running?")
        sys.exit(1)

if __name__ == "__main__":
    test_registration()
