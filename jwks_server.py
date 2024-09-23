from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
import jwt
import uuid

app = Flask(__name__)

# In-memory key storage (in production, use a secure key management system)
keys = {}

def generate_key_pair(expiry_days=30):
    private_key = rsa.generate_private_key(
        public_exponent=65537, #standard value used for public exponent
        key_size=2048 #key size in bits, currently considered secure for most applications
    )
    public_key = private_key.public_key()
    kid = str(uuid.uuid4())
    exp = datetime.now(timezone.utc) + timedelta(days=expiry_days)
    keys[kid] = {
        "private_key": private_key,
        "public_key": public_key,
        "exp": exp
    }
    return kid

def get_jwk(kid):
    key_data = keys[kid]
    public_key = key_data['public_key']
    numbers = public_key.public_numbers()
    return {
        "kid": kid,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": int_to_base64(numbers.n), #modulus
        "e": int_to_base64(numbers.e), #exponent
        "exp": int(key_data['exp'].timestamp())
    }

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return jwt.utils.base64url_encode(value_bytes).decode('ascii')

# Generate initial keys
current_kid = generate_key_pair()
expired_kid = generate_key_pair(-30)  # Generate an expired key

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    current_time = datetime.now(timezone.utc)
    unexpired_keys = []

    for kid, key_data in keys.items():
        if key_data['exp'] > current_time:
            jwk = get_jwk(kid)  # Assuming you have a get_jwk function
            unexpired_keys.append(jwk)

    return jsonify({"keys": unexpired_keys})

@app.route('/auth', methods=['POST'])
def authenticate():
    username = request.json.get('username', '')
    use_expired = request.args.get('expired', 'false').lower() == 'true'

    if use_expired:
        kid = expired_kid
    else:
        kid = current_kid

    key_data = keys[kid]

    payload = {
        "sub": username,
        "iat": datetime.now(timezone.utc),
        "exp": key_data['exp'] if use_expired else datetime.now(timezone.utc) + timedelta(hours=1),
    }

    headers = {
        "kid": kid
    }

    token = jwt.encode(payload, key_data['private_key'], algorithm="RS256", headers=headers)
    
    return jsonify({
        "token": token,
        "expires": payload['exp'].isoformat(),
        "used_expired_key": use_expired
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
