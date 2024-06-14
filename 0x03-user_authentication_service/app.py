#!/usr/bin/env python3
"""
Basic Flask app.
"""

from flask import Flask, jsonify, request, make_response
from flask import abort, redirect, url_for
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


@app.route('/sessions', methods=['DELETE'])
def logout():
    # Get session ID from the request cookies
    session_id = request.cookies.get('session_id')

    # Find the user with the session ID and destroy the session
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        AUTH.destroy_session(user.id)
        # Redirect the user to the index page after logout
        return redirect(url_for('index'))
    else:
        # If user does not exist, respond with 403 HTTP status
        abort(403)


@app.route('/profile', methods=['GET'])
def profile():
    # Get session ID from the request cookies
    session_id = request.cookies.get('session_id')

    # Find the user with the session ID
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        # If user exists, respond with a 200 HTTP status and the user's email
        return jsonify({"email": user.email}), 200
    else:
        # If session ID is invalid or user does not exist,
        # respond with a 403 HTTP status
        abort(403)


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token():
    # Get email from form data
    email = request.form.get('email')

    # Check if the email is registered
    try:
        reset_token = AUTH.get_reset_password_token(email)
        # If email is registered, respond with a 200 HTTP status and
        # the reset token
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except ValueError:
        # If email is not registered, respond with a 403 HTTP status
        abort(403)


@app.route('/reset_password', methods=['PUT'])
def update_password():
    """
    Updates password with reset token

    Returns:
        - 400 if bad request
        - 403 if not valid reset token
        - 200 and JSON Payload if valid
    """
    # Extract data from the request form
    try:
        email = request.form['email']
        reset_token = request.form['reset_token']
        new_password = request.form['new_password']
    except KeyError:
        # If any of the required fields are missing, return 400 Bad Request
        return jsonify({"message": "Bad request"}), 400

    try:
        # Try to update the password using the reset token
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        # If the reset token is invalid, return 403 Forbidden
        return jsonify({"message": "Invalid reset token"}), 403

    # If the password is updated successfully, return 200 OK
    return jsonify({"email": email, "message": "Password updated"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
