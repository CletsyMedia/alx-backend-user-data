#!/usr/bin/env python3
"""
Basic Flask app.
"""

from flask import Flask, jsonify, request, make_response, abort
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/")
def index():
    """
    Returns a JSON payload with a welcome message.
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def register_user():
    """
    Register a new user.
    """
    try:
        email = request.form["email"]
        password = request.form["password"]
    except KeyError:
        return jsonify({"message": "email and password are required"}), 400

    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"}), 200
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    # Get email and password from form data
    email = request.form.get('email')
    password = request.form.get('password')

    # Validate login credentials
    if not email or not password or not AUTH.valid_login(email, password):
        abort(401)

    # Create a new session for the user
    session_id = AUTH.create_session(email)

    # Set session ID as a cookie in the response
    response = make_response(jsonify({'email': email, 'message': 'logged in'}))
    response.set_cookie('session_id', session_id)

    return response



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
