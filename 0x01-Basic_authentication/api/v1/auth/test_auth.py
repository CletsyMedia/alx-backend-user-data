import unittest
from api.v1.auth.auth import Auth


class TestAuth(unittest.TestCase):

    def setUp(self):
        self.auth = Auth()

    def test_exact_matches(self):
        # Test exact matches for excluded paths
        excluded_paths = ["/api/v1/status"]
        self.assertFalse(self.auth.require_auth(
            "/api/v1/status", excluded_paths))
        self.assertTrue(self.auth.require_auth(
            "/api/v1/users", excluded_paths))

    def test_wildcard_matches(self):
        # Test wildcard matches for excluded paths
        excluded_paths = ["/api/v1/stat*"]
        self.assertFalse(self.auth.require_auth(
            "/api/v1/stats", excluded_paths))
        self.assertFalse(self.auth.require_auth(
            "/api/v1/stat", excluded_paths))
        self.assertTrue(self.auth.require_auth(
            "/api/v1/status", excluded_paths))

    def test_edge_cases(self):
        # Test edge cases
        # None path, empty excluded paths
        self.assertTrue(self.auth.require_auth(None, None))
        # Non-empty path, empty excluded paths
        self.assertTrue(self.auth.require_auth("/api/v1/users", []))


if __name__ == '__main__':
    unittest.main()
