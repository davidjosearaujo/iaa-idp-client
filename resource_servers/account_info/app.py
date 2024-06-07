import traceback
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect
from cryptography.hazmat.primitives import serialization
import jwt
from datetime import datetime, timezone
import os
from functools import wraps

from authorization import is_authorized

RESOURCE_SERVER_ID = 1

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ['SQLALCHEMY_DATABASE_URI']


def to_dict(obj):
    return {c.key: getattr(obj, c.key) for c in inspect(obj).mapper.column_attrs}


# Database
db = SQLAlchemy(app)


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(64), nullable=False)
    iban = db.Column(db.String(25), nullable=False, unique=True)
    creation_date = db.Column(
        db.DateTime, nullable=False, default=datetime.now(timezone.utc)
    )


if not os.path.exists("instance/database.db"):
    with app.app_context():
        db.create_all()
        dummy_accounts = [
            {"user_email": os.environ["CLIENT_EMAIL"], "iban": "PT50123456789012345678901"},
            {"user_email": "client@xpto.com","iban": "PT50183456711012341178901"},
        ]
        for user_data in dummy_accounts:
            user = Account(**user_data)
            db.session.add(user)
        db.session.commit()

# Endpoints


# Wrapper function to check the JWT token and do authorization
def authenticate_and_authorize(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            auth_header = request.headers.get("Authorization")

            if not auth_header:
                return jsonify({"msg": "Missing authorization header"}), 401

            token_parts = auth_header.split()

            if len(token_parts) != 2 or token_parts[0].lower() != "bearer":
                return jsonify({"msg": "Invalid authorization header"}), 401

            token = token_parts[1]

            try:
                idp_public_key = serialization.load_ssh_public_key(
                    open("./idp_id_rsa.pub", "r").read().encode()
                )
                jwt_token = jwt.decode(token, idp_public_key, algorithms="RS256")
                kwargs["user_info"] = jwt_token

                if not is_authorized(jwt_token, RESOURCE_SERVER_ID, request.url_rule.rule):
                    return jsonify({"msg": "Forbidden"}), 403

                return func(*args, **kwargs)
            except jwt.ExpiredSignatureError:
                return jsonify({"msg": "Token has expired"}), 403
            except jwt.InvalidTokenError:
                return jsonify({"msg": "Invalid token"}), 403
        except:
            traceback.print_exc()
            return jsonify({"msg": "Internal error"}), 500

    return wrapper


@app.route("/basic_info", methods=["GET"])
@authenticate_and_authorize
def basic_info(user_info):
    try:
        accounts = Account.query.filter_by(user_email=user_info["email"]).all()
        if accounts:
            accounts_to_return = []
            for account in accounts:
                accounts_to_return.append(to_dict(account))
            return jsonify({"accounts": accounts_to_return}), 200
        return jsonify({"msg": "Invalid parameters"}), 400
    except:
        traceback.print_exc()
        return jsonify({"msg": "Internal error"}), 500


if __name__ == "__main__":
    app.run()
