#!/usr/bin/env python3
"""
Auth module
"""
import bcrypt
from db import DB
from user import User
from uuid import uuid4
from typing import TypeVar
from sqlalchemy.orm.exc import NoResultFound


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


def _generate_uuid() -> str:
    """Returns a string representation of a new UUID"""
    UUID = uuid4()
    return str(UUID)


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
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            pass

        # Hash the password
        hashed_password = _hash_password(password)

        # Save user to the database
        user = self._db.add_user(email, hashed_password)

        return user

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate user credentials.

        Args:
            email: The email of the user.
            password: The password to be validated.

        Returns:
            bool: True if the credentials are valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(
                password.encode('utf-8'), user.hashed_password)
        except NoResultFound:
            return False

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

    def create_session(self, email: str) -> str:
        """
        Create a session for the user and return the session ID.

        Args:
            email: The email of the user.

        Returns:
            str: The session ID.
        """
        try:
            # Find the user by email
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        # Generate a new UUID for the session ID
        session_id = _generate_uuid()

        # Update the user's session ID in the database
        user.session_id = session_id
        self._db.update_user(user.id, session_id=session_id)

        return session_id

    def get_user_from_session_id(self, session_id: str) -> TypeVar('User'):
        """Gets a user from a session ID"""
        try:
            if session_id is None:
                return None
            user = self._db.find_user_by(session_id=session_id)
            return user
        except Exception:
            raise

    def destroy_session(self, user_id: int) -> None:
        """
        Destroy the session associated with the given user ID.

        Args:
            user_id: The ID of the user whose session is to be destroyed.
        """
        try:
            user = self._db.find_user_by(id=user_id)
            self._db.update_user(user.id, session_id=None)
        except NoResultFound:
            pass

    def get_reset_password_token(self, email: str) -> str:
        """
        Generate a reset password token for the user.

        Args:
            email: The email of the user.

        Returns:
            str: The reset password token.

        Raises:
            ValueError: If the user does not exist.
        """
        try:
            # Find the user by email
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            # If user does not exist, raise ValueError
            raise ValueError(f"User {email} does not exist")

        # Generate a new UUID for the reset password token
        reset_token = str(uuid4())

        # Update the user's reset_token in the database
        user.reset_token = reset_token
        self._db.update_user(user.id, reset_token=reset_token)

        return reset_token

    def update_password(self, reset_token: str, new_password: str) -> None:
        """
        Update user's password using reset token.

        Args:
            reset_token: The reset token to identify the user.
            new_password: The new password to be set.

        Returns:
            None

        Raises:
            ValueError: If the user does not exist.
        """
        try:
            # Find the user by reset token
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            # If user does not exist, raise ValueError
            raise ValueError("Invalid reset token")

        # Hash the new password
        hashed_password = self._hash_password(new_password)

        # Update user's hashed_password and reset_token fields in the database
        user.hashed_password = hashed_password
        user.reset_token = None
        self._db.update_user(
            user.id,
            hashed_password=hashed_password,
            reset_token=None)
