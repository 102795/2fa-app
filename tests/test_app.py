"""Unit tests for the 2FA app."""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

# Make the root package importable when running from the tests/ directory.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app as fa


class _TempDataMixin:
    """Redirect data storage to a temporary directory for each test."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._patch_data_dir = mock.patch.object(fa, "DATA_DIR", self._tmpdir.name)
        self._patch_users_file = mock.patch.object(
            fa, "USERS_FILE", os.path.join(self._tmpdir.name, "users.json")
        )
        self._patch_data_dir.start()
        self._patch_users_file.start()

    def tearDown(self):
        self._patch_data_dir.stop()
        self._patch_users_file.stop()
        self._tmpdir.cleanup()


class TestCreateAccount(_TempDataMixin, unittest.TestCase):

    def test_create_account_success(self):
        ok, msg = fa.create_account("alice", "s3cr3t")
        self.assertTrue(ok)
        self.assertIn("success", msg.lower())

    def test_create_account_duplicate(self):
        fa.create_account("alice", "s3cr3t")
        ok, msg = fa.create_account("alice", "other")
        self.assertFalse(ok)
        self.assertIn("already taken", msg.lower())

    def test_create_account_empty_username(self):
        ok, msg = fa.create_account("", "password")
        self.assertFalse(ok)

    def test_create_account_empty_password(self):
        ok, msg = fa.create_account("bob", "")
        self.assertFalse(ok)

    def test_create_account_stores_hashed_password(self):
        fa.create_account("carol", "mypassword")
        users = fa._load_users()
        self.assertIn("carol", users)
        # Password must NOT be stored in plaintext.
        self.assertNotEqual(users["carol"]["password_hash"], "mypassword")


class TestLogin(_TempDataMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        fa.create_account("dave", "hunter2")

    def test_login_success(self):
        ok, msg = fa.login("dave", "hunter2")
        self.assertTrue(ok)
        self.assertIn("success", msg.lower())

    def test_login_wrong_password(self):
        ok, msg = fa.login("dave", "wrong")
        self.assertFalse(ok)
        self.assertIn("invalid", msg.lower())

    def test_login_unknown_user(self):
        ok, msg = fa.login("nobody", "password")
        self.assertFalse(ok)
        self.assertIn("invalid", msg.lower())

    def test_login_empty_credentials(self):
        ok, _ = fa.login("", "")
        self.assertFalse(ok)


class TestKeyManagement(_TempDataMixin, unittest.TestCase):
    # Use a well-known test secret (RFC 6238 example).
    VALID_SECRET = "JBSWY3DPEHPK3PXP"

    def setUp(self):
        super().setUp()
        fa.create_account("eve", "password")

    def test_add_key_success(self):
        ok, msg = fa.add_key("eve", "GitHub", self.VALID_SECRET)
        self.assertTrue(ok)
        self.assertIn("saved", msg.lower())

    def test_add_key_invalid_secret(self):
        ok, msg = fa.add_key("eve", "Bad", "not-a-valid-secret!!!")
        self.assertFalse(ok)
        self.assertIn("invalid", msg.lower())

    def test_add_key_empty_name(self):
        ok, msg = fa.add_key("eve", "", self.VALID_SECRET)
        self.assertFalse(ok)

    def test_add_key_whitespace_in_secret(self):
        # Secrets copied from authenticator apps often contain spaces.
        spaced = "JBSW Y3DP EHPK 3PXP"
        ok, msg = fa.add_key("eve", "Spaced", spaced)
        self.assertTrue(ok)

    def test_delete_key_success(self):
        fa.add_key("eve", "GitHub", self.VALID_SECRET)
        ok, msg = fa.delete_key("eve", "GitHub")
        self.assertTrue(ok)
        self.assertIn("deleted", msg.lower())

    def test_delete_key_not_found(self):
        ok, msg = fa.delete_key("eve", "NonExistent")
        self.assertFalse(ok)
        self.assertIn("not found", msg.lower())

    def test_delete_key_unknown_user(self):
        ok, msg = fa.delete_key("ghost", "key")
        self.assertFalse(ok)


class TestGetCodes(_TempDataMixin, unittest.TestCase):
    VALID_SECRET = "JBSWY3DPEHPK3PXP"

    def setUp(self):
        super().setUp()
        fa.create_account("frank", "password")

    def test_get_codes_empty(self):
        codes = fa.get_codes("frank")
        self.assertEqual(codes, [])

    def test_get_codes_returns_entries(self):
        fa.add_key("frank", "MyService", self.VALID_SECRET)
        codes = fa.get_codes("frank")
        self.assertEqual(len(codes), 1)
        entry = codes[0]
        self.assertEqual(entry["name"], "MyService")
        self.assertRegex(entry["code"], r"^\d{6}$")
        self.assertGreaterEqual(entry["seconds_remaining"], 0)
        self.assertLessEqual(entry["seconds_remaining"], 30)

    def test_get_codes_multiple_keys(self):
        fa.add_key("frank", "GitHub", self.VALID_SECRET)
        fa.add_key("frank", "GitLab", self.VALID_SECRET)
        codes = fa.get_codes("frank")
        names = {c["name"] for c in codes}
        self.assertEqual(names, {"GitHub", "GitLab"})

    def test_get_codes_unknown_user(self):
        codes = fa.get_codes("ghost")
        self.assertEqual(codes, [])


if __name__ == "__main__":
    unittest.main()
