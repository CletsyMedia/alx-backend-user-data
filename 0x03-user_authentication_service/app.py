#!/usr/bin/env python3
"""
Basic Flask app.
"""

from flask import Flask, jsonify
from auth import Auth

app = Flask(__name__)
auth = Auth()


@app.route("/")
def index():
    """
    Returns a JSON payload with a welcome message.
    """
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
