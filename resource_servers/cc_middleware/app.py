from flask import Flask, jsonify, request
from flask_cors import CORS
import os
from cryptography.hazmat.primitives import serialization
import jwt
import json

from cc_interface import sign_message

app = Flask(__name__, static_url_path="/static")
app.config["SECRET_KEY"] = "secret"
CORS(app)


def is_token_valid(token):
    try:
        idp_public_key = serialization.load_ssh_public_key(
            open("./idp_id_rsa.pub", "r").read().encode()
        )
        jwt_token = jwt.decode(token, idp_public_key, algorithms="RS256")
        return True if "cc" in jwt_token.get("access_whitelist") else False
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False


@app.route("/sign", methods=["POST"])
def sign():
    try:
        token = request.headers.get("Authorization")
        if not is_token_valid(token):
            return jsonify({"msg": "Forbidden"}), 405
        message = json.loads(request.data).get("message")
        if not message:
            return jsonify({"msg": "Invalid arguments"}), 400
        signature, certificate = sign_message(message)
        if signature == None:
            return jsonify({"msg": "Unable to sign"}), 412
        if signature == 1:
            return jsonify({"msg": "Please insert the card"}), 415
        return jsonify({"signature": signature, "certificate": certificate}), 200
    except:
        return jsonify({"msg": "Internal Error"}), 500


if __name__ == "__main__":
    app.run()
