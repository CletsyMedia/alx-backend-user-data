#!/usr/bin/env python3
"""
Session authentication
"""
from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession
from datetime import datetime
from os import getenv


class SessionDBAuth(SessionExpAuth):
    """Session authentication with database"""

    def create_session(self, user_id=None) -> str:
        """Create and store a new UserSession instance"""
        session_id = super().create_session(user_id)
        if session_id:
            new_session = UserSession(user_id=user_id, session_id=session_id)
            new_session.save()
            return session_id
        return None

    def user_id_for_session_id(self, session_id=None) -> str:
        """Return user ID for Session ID from the database"""
        if session_id is None:
            return None

        user_session = UserSession.search({'session_id': session_id})
        if not user_session:
            return None

        user_session = user_session[0]
        return super().user_id_for_session_id(session_id)

    def destroy_session(self, request=None) -> bool:
        """Destroy UserSession based on Session ID from the request cookie"""
        if request is None:
            return False

        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        user_session = UserSession.search({'session_id': session_id})
        if not user_session:
            return False

        user_session = user_session[0]
        user_session.remove()
        return super().destroy_session(request)
