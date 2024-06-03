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

RESOURCE_SERVER_ID = 2

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ['SQLALCHEMY_DATABASE_URI']

def to_dict(obj):
    return {c.key: getattr(obj, c.key) for c in inspect(obj).mapper.column_attrs}


# Database
db = SQLAlchemy(app)


class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_email = db.Column(db.String(64), nullable=False)
    state = db.Column(db.Boolean, default=False)
    total_value = db.Column(db.Float, nullable=False)
    paid_value = db.Column(db.Float, nullable=False)
    payment_iban = db.Column(db.String(25), nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    rate_type = db.Column(db.String(32))
    n_payments = db.Column(db.Integer, nullable=False)
    n_payments_done = db.Column(db.Integer, nullable=False)
    payment_day_of_month = db.Column(db.Integer, nullable=False)
    creation_date = db.Column(
        db.DateTime, nullable=False, default=datetime.now(timezone.utc)
    )


if not os.path.exists("instance/database.db"):
    with app.app_context():
        db.create_all()
        dummy_accounts = [
            {
                "client_email": os.environ["CLIENT_EMAIL"],
                "total_value": 15000.0,
                "paid_value": 673.50,
                "interest_rate": 2.8,
                "rate_type": "fixed",
                "n_payments": 12,
                "n_payments_done": 2,
                "payment_day_of_month": 3,
                "payment_iban": "PT50123456789012345678901",
            },
        ]
        for user_data in dummy_accounts:
            user = Loan(**user_data)
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


# Get the loans of the client
@app.route("/loans", methods=["GET"])
@authenticate_and_authorize
def loans(user_info):
    try:
        loans = Loan.query.filter_by(client_email=user_info["email"]).all()
        if loans:
            loans_to_return = []
            for loan in loans:
                loans_to_return.append(to_dict(loan))
            return jsonify(loans_to_return), 200
        return jsonify({"msg": "Invalid parameters"}), 400
    except:
        traceback.print_exc()
        return jsonify({"msg": "Internal error"}), 500


# Get the value of the next payment of a given loan
@app.route("/next_payment_value/<loan_id>", methods=["GET"])
@authenticate_and_authorize
def next_payment(user_info, loan_id):
    try:
        loan = Loan.query.filter_by(id=loan_id).first()
        if loan:
            if loan.client_email != user_info["email"]:
                return jsonify({"msg": "Forbidden"}), 403
            return (
                jsonify(
                    {
                        "amount": loan.total_value
                        / loan.paid_value
                        * (1 + loan.interest_rate / 100)
                    }
                ),
                200,
            )
        return jsonify({"msg": "Invalid parameters"}), 400
    except:
        traceback.print_exc()
        return jsonify({"msg": "Internal error"}), 500


if __name__ == "__main__":
    app.run()
