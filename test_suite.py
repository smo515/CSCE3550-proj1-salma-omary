import requests
import jwt
from datetime import datetime, timedelta, timezone

BASE_URL = 'http://localhost:8080'

def get_jwks():
    response = requests.get(f'{BASE_URL}/.well-known/jwks.json')
    return response.json()['keys']

def get_public_key(kid, jwks):
    for key in jwks:
        if key['kid'] == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(key)
    return None

def verify_token(token, jwks):
    try:
        headers = jwt.get_unverified_header(token)
        kid = headers.get('kid')
        if not kid:
            print("No 'kid' found in token header")
            return False
        
        public_key = get_public_key(kid, jwks)
        
        if not public_key:
            print(f"Public key not found for kid: {kid}")
            return False
        
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        print("Token verified successfully.")
        print("Payload:", payload)
        return True
    except jwt.ExpiredSignatureError:
        print("Token has expired.")
        return False
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {str(e)}")
        return False

def get_token(expired=False):
    url = f'{BASE_URL}/auth'
    if expired:
        url += '?expired=true'
    response = requests.post(url, json={'username': 'testuser'})
    return response.json()['token']

def test_valid_jwt():
    print("\n1. Testing valid JWT authentication:")
    token = get_token()
    jwks = get_jwks()
    verify_token(token, jwks)

def test_expired_jwt():
    print("\n2. Testing when /auth returns an expired JWT:")
    token = get_token(expired=True)
    jwks = get_jwks()
    verify_token(token, jwks)

def test_valid_kid_in_jwks():
    print("\n3. Testing when a valid JWT's kid is found in JWKS:")
    token = get_token()
    jwks = get_jwks()
    headers = jwt.get_unverified_header(token)
    kid = headers.get('kid')
    if kid:
        public_key = get_public_key(kid, jwks)
        if public_key:
            print(f"Public key found for kid: {kid}")
        else:
            print(f"Public key not found for kid: {kid}")
    else:
        print("No 'kid' found in token header")

def test_expired_kid_not_in_jwks():
    print("\n4. Testing when the expired JWT's kid is not found in JWKS:")
    token = get_token(expired=True)
    jwks = get_jwks()
    headers = jwt.get_unverified_header(token)
    kid = headers.get('kid')
    if kid:
        public_key = get_public_key(kid, jwks)
        if public_key:
            print(f"Public key found for kid: {kid}")
        else:
            print(f"Public key not found for kid: {kid}")
    else:
        print("No 'kid' found in token header")

def test_jwt_expiry_in_past():
    print("\n5. Testing when the JWT expiry claim is in the past:")
    token = get_token()
    payload = jwt.decode(token, options={"verify_signature": False})
    payload['exp'] = datetime.now(timezone.utc) - timedelta(hours=1)
    headers = jwt.get_unverified_header(token)
    private_key = jwt.algorithms.RSAAlgorithm.generate_key(2048)
    expired_token = jwt.encode(payload, private_key, algorithm='RS256', headers=headers)
    jwks = get_jwks()
    verify_token(expired_token, jwks)

if __name__ == '__main__':
    test_valid_jwt()
    test_expired_jwt()
    test_valid_kid_in_jwks()
    test_expired_kid_not_in_jwks()
    test_jwt_expiry_in_past()
