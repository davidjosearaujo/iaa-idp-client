import traceback
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, or_
from cryptography.hazmat.primitives import serialization
import jwt
from datetime import datetime, timezone
import os
from functools import wraps

from authorization import is_authorized

RESOURCE_SERVER_ID = 3

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ['SQLALCHEMY_DATABASE_URI']


def to_dict(obj):

    return {c.key: getattr(obj, c.key) for c in inspect(obj).mapper.column_attrs}


# Database
db = SQLAlchemy(app)


class Balance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_email = db.Column(
        db.String(64),
        unique=True
    )  # This is redundant but this way we don't need to query the account information server!
    iban = db.Column(db.String(25), nullable=False, unique=True)
    balance = db.Column(db.Float, nullable=False)
    creation_date = db.Column(
        db.DateTime, nullable=False, default=datetime.now(timezone.utc)
    )


class Movement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    iban_from = db.Column(db.String(25), nullable=False)
    iban_to = db.Column(db.String(25), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    execution_date = db.Column(
        db.DateTime, nullable=False, default=datetime.now(timezone.utc)
    )


if not os.path.exists("instance/database.db"):
    with app.app_context():
        db.create_all()
        dummy_balances = [
            {
                "iban": "PT50123456789012345678901",
                "balance": 1300.34,
                "client_email": os.environ["CLIENT_EMAIL"],
            },
            {
                "iban": "PT50183456711012341178901",
                "balance": 12345.67,
                "client_email": "client_2@xpto.com",
            },
        ]
        dummy_movements = [
            {
                "iban_from": "PT50123456789012345678901",
                "iban_to": "PT50183456711012341178901",
                "amount": 15.0,
            },
        ]
        for user_data in dummy_balances:
            data = Balance(**user_data)
            db.session.add(data)
        for user_data in dummy_movements:
            data = Movement(**user_data)
            db.session.add(data)
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
                return jsonify({"msg": "Token has expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"msg": "Invalid token"}), 401
        except:
            traceback.print_exc()
            return jsonify({"msg": "Internal error"}), 500

    return wrapper


@app.route("/balance/<iban>", methods=["GET"])
@authenticate_and_authorize
def balance(user_info, iban):
    try:
        balance = Balance.query.filter_by(iban=iban).first()
        if balance.client_email != user_info["email"]:
            return jsonify({"msg": "Forbidden"}), 403
        return jsonify(balance.balance), 200
    except:
        traceback.print_exc()
        return jsonify({"msg": "Internal error"}), 500


@app.route("/movements/<iban>", methods=["GET"])
@authenticate_and_authorize
def movements(user_info, iban):
    try:
        balance = Balance.query.filter_by(iban=iban).first()
        if balance:
            if balance.client_email != user_info["email"]:
                return jsonify({"msg": "Forbidden"}), 403
            movements = Movement.query.filter(or_(Movement.iban_to == iban, Movement.iban_from == iban)).all()
            movements_to_return = []
            for movement in movements:
                movements_to_return.append(to_dict(movement))
            return jsonify(movements_to_return), 200
        return jsonify({"msg": "Invalid parameters"}), 400
    except:
        traceback.print_exc()
        return jsonify({"msg": "Internal error"}), 500


@app.route("/transfer", methods=["POST"])
@authenticate_and_authorize
def transfer(user_info):
    try:
        print(request.form)
        iban_from = request.form.get("from")
        iban_to = request.form.get("to")
        amount = float(request.form.get("amount"))

        if iban_from and iban_to:
            balance_from = Balance.query.filter_by(iban=iban_from).first()
            balance_to = Balance.query.filter_by(iban=iban_to).first()

            if balance_from and balance_to:
                if balance_from.client_email != user_info["email"]:
                    return jsonify({"msg": "Forbidden"}), 403

                if balance_from.balance >= amount:
                    balance_from.balance -= amount
                    balance_to.balance += amount
                    db.session.add(
                        Movement(iban_from=iban_from, iban_to=iban_to, amount=amount)
                    )
                    db.session.commit()
                    return jsonify({"msg": "Operation successful"}), 200
                else:
                    return jsonify({"msg": "Insufficient capital"}), 400

        return jsonify({"msg": "Invalid parameters"}), 400
    except:
        traceback.print_exc()
        return jsonify({"msg": "Internal error"}), 500


if __name__ == "__main__":
    app.run()
