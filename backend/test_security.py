import os
import tempfile
import unittest

from backend.app import create_app
from backend.models import initialize_schema


class SecurityFlowTests(unittest.TestCase):
    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(prefix="secure-login-", suffix=".db")
        os.environ["DATABASE_PATH"] = self.db_path
        self.app = create_app()
        self.client = self.app.test_client()
        initialize_schema(self.db_path)
        self.csrf_token = self.client.get("/api/csrf-token").get_json()["csrf_token"]

    def tearDown(self):
        os.close(self.db_fd)
        os.remove(self.db_path)

    def _post(self, path, payload):
        return self.client.post(path, json=payload, headers={"X-CSRF-Token": self.csrf_token})

    def test_register_login_lockout_and_reset(self):
        register = self._post(
            "/api/auth/register",
            {"username": "alice", "email": "alice@example.com", "password": "Strong#123"},
        )
        self.assertEqual(register.status_code, 201)

        bad_login = self._post("/api/auth/login", {"username": "alice", "password": "wrongpass"})
        self.assertEqual(bad_login.status_code, 401)
        self._post("/api/auth/login", {"username": "alice", "password": "wrongpass"})
        locked = self._post("/api/auth/login", {"username": "alice", "password": "wrongpass"})
        self.assertIn(locked.status_code, [401, 423])

        forgot = self._post("/api/auth/forgot-password", {"email": "alice@example.com"})
        self.assertEqual(forgot.status_code, 200)

    def test_csrf_rejected_when_missing(self):
        response = self.client.post("/api/auth/register", json={})
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
