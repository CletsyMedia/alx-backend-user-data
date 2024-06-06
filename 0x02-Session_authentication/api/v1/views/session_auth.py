#!/usr/bin/env python3
"""
Session authentication view
"""
from flask import request, jsonify, current_app
from api.v1.views import app_views
from models.user import User

# Import the auth object from the app module
from api.v1.app import auth


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_login():
    """ Handle session login """
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email:
            return jsonify({"error": "email missing"}), 400
        if not password:
            return jsonify({"error": "password missing"}), 400

        user = User.search({'email': email})
        if not user:
            return jsonify({"error": "no user found for this email"}), 404
        user = user[0]  # Get the first user object from the list

        if not user.is_valid_password(password):
            return jsonify({"error": "wrong password"}), 401

        # Use the auth object to create a session ID
        session_id = auth.create_session(user.id)
        response = jsonify(user.to_json())
        # Set the cookie using the SESSION_NAME from the app configuration
        response.set_cookie(current_app.config['SESSION_NAME'], session_id)
        return response

    # Return Method Not Allowed for GET requests
    return jsonify({"error": "Method Not Allowed"}), 405
