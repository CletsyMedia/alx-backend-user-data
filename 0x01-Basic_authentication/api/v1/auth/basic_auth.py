#!/usr/bin/env python3
"""
BasicAuth module
"""
import base64
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
