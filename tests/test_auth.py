import time
import unittest

from auth import create_hs256_jwt, verify_hs256_jwt


class AuthTests(unittest.TestCase):
    def test_jwt_roundtrip(self) -> None:
        token = create_hs256_jwt(secret="abc123", subject="tester", ttl_seconds=120, extra_claims={"role": "admin"})
        claims = verify_hs256_jwt(token, "abc123")
        self.assertEqual(claims["sub"], "tester")
        self.assertEqual(claims["role"], "admin")

    def test_jwt_expired(self) -> None:
        token = create_hs256_jwt(secret="abc123", subject="tester", ttl_seconds=1)
        time.sleep(2)
        with self.assertRaises(ValueError):
            verify_hs256_jwt(token, "abc123", leeway_seconds=0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
