import traceback
from flask import Flask, session, request, redirect, render_template
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
import os
import jwt
import requests
from functools import wraps

app = Flask(__name__, static_url_path="/static")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ['SQLALCHEMY_DATABASE_URI']
app.config["SECRET_KEY"] = os.environ['SECRET_KEY']


def current_user():
    if (
        "id" in session
    ):  # no validity since this is just an internal identifier and login can be enforced
        # even if this method still return the user object
        uid: int = session["id"]
        return User.query.get(uid)
    return None


# Database
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(1024), nullable=True)
    refresh_token = db.Column(db.String(62), nullable=True)
    creation_datetime = db.Column(
        db.DateTime, nullable=False, default=datetime.now(timezone.utc)
    )


if not os.path.exists("instance/database.db"):
    with app.app_context():
        db.create_all()


def try_refresh_access_token(refresh_token):
    try:
        if not refresh_token:
            return None
        response = requests.post(
            os.environ['IDP']+"/oauth/token",
            auth=(os.environ['MY_CLIENT_ID'], os.environ['MY_CLIENT_SECRET']),
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )
        print(response.json())
        return response.json().get("token")
    except:
        return None


# Endpoints
def authenticate_and_authorize(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            user = current_user()
            authentication_code = request.args.get("code")
            has_new_token = False
            if authentication_code:
                response = requests.post(
                    f"{os.environ['IDP']}/oauth/token",
                    auth=(os.environ['MY_CLIENT_ID'], os.environ['MY_CLIENT_SECRET']),
                    data={
                        "grant_type": "authorization_code",
                        "include_refresh_token": 1,
                        "scope": "profile",
                        "code": authentication_code,
                    },
                )
                if response.status_code == 200:
                    token = response.json().get("token")
                    refresh_token = response.json().get("refresh_token")
                    if user:
                        user.access_token = token
                        user.refresh_token = refresh_token
                        db.session.commit()
                        has_new_token = True
                    else:
                        user = User(access_token=token, refresh_token=refresh_token)
                        db.session.add(user)
                        db.session.commit()
                        has_new_token = True
                        session["id"] = user.id

            if not user or not user.access_token:
                return redirect(
                    f"http://127.0.0.1:5000/oauth/authorize?response_type=code&client_id={os.environ['MY_CLIENT_ID']}&scope=profile"
                )
            try:
                idp_public_key = serialization.load_ssh_public_key(
                    open("./idp_id_rsa.pub", "r").read().encode()
                )
                user_info = jwt.decode(
                    user.access_token, idp_public_key, algorithms="RS256"
                )
                kwargs["token"] = user.access_token
                kwargs["user_info"] = user_info
                if has_new_token:
                    return redirect("/")
                return func(*args, **kwargs)
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                new_token = try_refresh_access_token(user.refresh_token)
                if not new_token:
                    return (
                        redirect(
                            f"http://127.0.0.1:5000/oauth/authorize?response_type=code&client_id={os.environ['MY_CLIENT_ID']}&scope=profile"
                        )
                        if not has_new_token
                        else render_template("403.html")
                    ), 403
                idp_public_key = serialization.load_ssh_public_key(
                    open("./idp_id_rsa.pub", "r").read().encode()
                )
                user_info = jwt.decode(
                    user.access_token, idp_public_key, algorithms="RS256"
                )
                user.access_token = new_token
                db.session.commit()
                kwargs["token"] = user.access_token
                kwargs["user_info"] = user_info
                return func(*args, **kwargs)
        except:
            traceback.print_exc()
            return render_template("500.html"), 500

    return wrapper


@app.route("/",  methods=["GET"])
@authenticate_and_authorize
def home(token, user_info):
    try:
        return f"Hi, {user_info.get('email')}. This is the Bank Managing Service for officers..."
    except:
        return render_template("500.html"), 500

if __name__ == "__main__":
    app.run()
