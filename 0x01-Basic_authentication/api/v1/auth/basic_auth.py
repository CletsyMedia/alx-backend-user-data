#!/usr/bin/env python3
"""
BasicAuth module
"""
import base64
from typing import TypeVar
from models.user import User
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ BasicAuth class """
    pass

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """Extracts the Base64 part of the Authorization header
        for Basic Authentication"""
        if authorization_header is None or not isinstance(
                authorization_header, str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header.split(" ")[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Decodes the Base64 part of the Authorization header"""
        if (base64_authorization_header is None or
                not isinstance(base64_authorization_header, str)):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except base64.binascii.Error:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """Extracts user email and password from the decoded Base64 string"""
        if (decoded_base64_authorization_header is None or
                not isinstance(decoded_base64_authorization_header, str)):
            return None, None

        if ":" not in decoded_base64_authorization_header:
            return None, None

        user_email, user_password = decoded_base64_authorization_header.split(
            ":")
        return user_email, user_password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Returns the User instance based on email and password"""
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        # Search for the user in the database
        user_instances = User.search({'email': user_email})

        if not user_instances:
            return None

        # Assuming there's only one user with the given email
        user_instance = user_instances[0]

        # Check if the provided password matches the user's password
        if not user_instance.is_valid_password(user_pwd):
            return None

        return user_instance
