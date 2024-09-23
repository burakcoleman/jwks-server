import unittest
import requests

BASE_URL = "http://localhost:8080"

class TestJWKSApp(unittest.TestCase):
    def test_jwks_endpoint(self):
        """
        Test the /.well-known/jwks.json endpoint to ensure it returns active keys.
        """
        response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("keys", data)
        self.assertTrue(len(data["keys"]) > 0, "No keys found in JWKS response")

    def test_auth_endpoint(self):
        """
        Test the /auth endpoint to ensure it returns a JWT token.
        """
        response = requests.post(f"{BASE_URL}/auth")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("token", data, "No token found in auth response")

    def test_auth_expired_key(self):
        """
        Test the /auth endpoint with the 'expired=true' parameter to ensure it returns a JWT token with an expired key.
        """
        response = requests.post(f"{BASE_URL}/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("token", data, "No token found in auth response")
        token = data["token"]

        # Check the structure of the JWT.
        parts = token.split(".")
        self.assertEqual(len(parts), 3, "JWT should have 3 parts")

if __name__ == '__main__':
    unittest.main()

