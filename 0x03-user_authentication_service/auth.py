#!/usr/bin/env python3
"""
Auth module
"""
import bcrypt
from db import DB
from user import User

def _hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt hashpw

    Args:
        password: A string representing the password to be hashed

    Returns:
        Bytes: A salted hash of the input password
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Register a new user.

        Args:
            email: The email of the user.
            password: The password of the user.

        Returns:
            User: The newly registered user object.

        Raises:
            ValueError: If the user already exists.
        """
        # Check if user already exists
        if self._db.find_user_by_email(email):
            raise ValueError(f"User {email} already exists")

        # Hash the password
        hashed_password = _hash_password(password)

        # Save user to the database
        user = User(email, hashed_password)
        self._db.add_user(user)

        return user

if __name__ == "__main__":
    print(_hash_password("Hello Holberton"))
