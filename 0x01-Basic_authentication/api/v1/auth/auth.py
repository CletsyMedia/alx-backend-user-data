#!/usr/bin/env python3
"""
Auth module
"""
from flask import request


class Auth:
    """ Auth class """

    def require_auth(self, path: str, excluded_paths: list) -> bool:
        """ Checks if authentication is required for the given path """
        return False

    def authorization_header(self, request=None) -> str:
        """ Retrieves the authorization header from the request """
        return None

    def current_user(self, request=None) -> str:
        """ Retrieves the current user """
        return None
