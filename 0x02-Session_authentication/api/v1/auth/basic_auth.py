#!/usr/bin/env python3
"""
BasicAuth module
"""
import base64
from typing import TypeVar, Union
from models.user import User
from api.v1.auth.auth import Auth

T = TypeVar('T')


class BasicAuth(Auth):
    """ BasicAuth class """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Extracts the Base64 part of the Authorization header
        for Basic Authentication
        """
        if authorization_header is None or not isinstance(
                authorization_header, str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header.split(" ")[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Decodes the Base64 part of the Authorization header
        """
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
        """
        Extracts user email and password from the decoded Base64 string
        """
        if (decoded_base64_authorization_header is None or
                not isinstance(decoded_base64_authorization_header, str)):
            return None, None

        decoded_string = decoded_base64_authorization_header.split(':', 1)
        if len(decoded_string) != 2:
            return None, None

        user_email, user_password = decoded_string
        return user_email, user_password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
        Returns the User instance based on email and password
        """
        if not user_email or not isinstance(user_email, str) or \
                not user_pwd or not isinstance(user_pwd, str):
            return None
        users = User.search({'email': user_email})
        if not users:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the User instance for a request using Basic Authentication.
        """
        if request is None:
            return None

        authorization_header = request.headers.get('Authorization')
        if not authorization_header or \
                not authorization_header.startswith('Basic '):
            return None

        base64_credentials = self.extract_base64_authorization_header(
            authorization_header)
        if not base64_credentials:
            return None

        decoded_credentials = self.decode_base64_authorization_header(
            base64_credentials)
        if not decoded_credentials:
            return None

        user_email, user_password = self.extract_user_credentials(
            decoded_credentials)
        if not user_email or not user_password:
            return None

        return self.user_object_from_credentials(user_email, user_password)
