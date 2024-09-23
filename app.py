from flask import Flask, jsonify, request
import jwt
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Store keys
keys = []

# Generate a JWK-compliant dictionary from an RSA public key
def jwk_from_public_key(public_key, kid):
    public_numbers = public_key.public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    return {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": kid,
        "n": format(n, 'x'),  # modulus in hex
        "e": format(e, 'x')   # exponent in hex
    }

# Generate RSA key pair with expiry and kid
def generate_rsa_keypair(kid, expiry_duration=3600):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()
    keys.append({
        "private_key": private_key,
        "public_key": public_key,
        "kid": kid,
        "expiry": time.time() + expiry_duration
    })
    return private_key, public_key

# JWKS endpoint to serve public keys
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    # Only include active keys
    active_keys = [jwk_from_public_key(key['public_key'], key['kid']) for key in keys if time.time() < key['expiry']]
    return jsonify({"keys": active_keys})

# /auth endpoint to issue a JWT
@app.route('/auth', methods=['POST'])
def auth():
    # Handle "expired" query parameter
    use_expired = 'expired' in request.args

    if use_expired:
        # Find an expired key
        expired_keys = [key for key in keys if time.time() > key['expiry']]
        if not expired_keys:
            return jsonify({"error": "No expired keys available"}), 400
        key_to_use = expired_keys[0]
    else:
        # Use an active key
        active_keys = [key for key in keys if time.time() < key['expiry']]
        if not active_keys:
            return jsonify({"error": "No active keys available"}), 400
        key_to_use = active_keys[0]

    private_key = key_to_use['private_key']
    kid = key_to_use['kid']
    expiry = key_to_use['expiry'] if use_expired else time.time() + 3600

    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": time.time(),
        "exp": expiry  # Expiry in payload
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})
    return jsonify({"token": token})

if __name__ == '__main__':
    # Generate initial keys
    generate_rsa_keypair(kid="1")  # Active key
    generate_rsa_keypair(kid="2", expiry_duration=-3600)  # Expired key

    app.run(port=8080)

