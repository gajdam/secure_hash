import unittest

from main import PasswordManager, SecurePasswordManager


class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        self.manager = PasswordManager(":memory:")

    def test_store_and_verify_password(self):
        password = "test_password"
        self.manager.store_password(password)
        self.assertTrue(self.manager.verify_password(password))

    def test_store_and_verify_wrong_password(self):
        correct_password = "correct_password"
        wrong_password = "wrong_password"
        self.manager.store_password(correct_password)
        self.assertFalse(self.manager.verify_password(wrong_password))


class TestSecurePasswordManager(unittest.TestCase):
    def setUp(self):
        self.secure_manager = SecurePasswordManager(":memory:")

    def test_store_and_verify_password(self):
        password = "test_password"
        self.secure_manager.store_password(password)
        self.assertTrue(self.secure_manager.verify_password(password))

    def test_store_and_verify_wrong_password(self):
        correct_password = "correct_password"
        wrong_password = "wrong_password"
        self.secure_manager.store_password(correct_password)
        self.assertFalse(self.secure_manager.verify_password(wrong_password))


if __name__ == '__main__':
    unittest.main()
