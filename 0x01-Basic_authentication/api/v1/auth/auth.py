#!/usr/bin/env python3
"""
Auth module
"""
from typing import List
from flask import request


class Auth:
    """ Auth class """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Checks if authentication is required for the given path """
        if path is None:
            return True

        if not excluded_paths:
            return True

        # Ensure that paths with and without trailing slashes are treated equally
        path = path.rstrip('/')
        excluded_paths = [p.rstrip('/') for p in excluded_paths]

        return path not in excluded_paths

    def authorization_header(self, request=None) -> str:
        """ Retrieves the authorization header from the request """
        return None

    def current_user(self, request=None):
        """ Retrieves the current user """
        return None
