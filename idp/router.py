import time
import traceback
import secrets
import base64
import re
import json
import urllib.parse
from flask import Blueprint, request, session, url_for, jsonify
from flask import render_template, redirect
from authlib.oauth2 import OAuth2Error
from models import User, OTP
from oauth import authorization
from models import db, User, Context, OAuth2Client

import oauth

bp = Blueprint("home", __name__)


def current_user():
    if "id" in session and session["id"]:
        if session.get("ts") and session["ts"] + 120 > int(
            time.time()
        ):  # session lasts for 1 minute
            uid: int = session["id"]
            return User.query.get(uid)
    return None


@bp.route("/", methods=["GET", "POST"])
def home():
    try:
        if not request.args.get("client_id", None, type=str):
            traceback.print_exc()
            return (
                render_template(
                    "index.html",
                    error_msg="Bad Request",
                ),
                400,
            )

        user: User = current_user()

        levels = Context.get_levels(
            user=user,
            current_ip=request.remote_addr,
            client_id=request.args.get("client_id", None, type=str),
        )

        current_context: Context = Context(
            user_id=getattr(user, "id", None),
            timestamp=int(time.time()),
            ip=request.remote_addr,
            login=0,
            method=getattr(user, "login_current_step", None),
        )

        if request.method == "POST":
            if not user or user.login_current_step == "password":
                email: str = request.form.get("email")
                user: User = User.query.filter_by(email=email).first()
                if (
                    not user
                    or user.is_registered != 1
                    or not user.check_password(request.form.get("password"))
                ):
                    if user:
                        user.login_current_step = levels[0]
                        current_context.method = levels[0]
                        current_context.user_id = user.id
                        session["id"] = None
                    session["ts"] = None

                    current_context.login = 1
                    db.session.add(current_context)
                    db.session.commit()

                    return render_template(
                        "index.html", auth_type="password", error_msg="Invalid Login"
                    )
                session["id"] = user.id
                session["ts"] = int(time.time())

            elif user.login_current_step == "eotp":
                if not OTP.verify_otp(user.id, request.form.get("otp")):
                    user.login_current_step = levels[0]
                    current_context.login = 1
                    current_context.method = user.login_current_step
                    db.session.add(current_context)
                    db.session.commit()
                    session["id"] = None
                    session["ts"] = None
                    return render_template(
                        "index.html",
                        auth_type=user.login_current_step,
                        error_msg="Invalid Login",
                    )

            elif user.login_current_step in ["totp", "hotp"]:
                if user.login_current_step == "totp":
                    check = user.check_totp(int(request.form.get("otp")))
                else:
                    check = user.check_hotp(int(request.form.get("otp")))
                if not check:
                    user.login_current_step = levels[0]
                    current_context.login = 1
                    current_context.method = user.login_current_step
                    db.session.add(current_context)
                    db.session.commit()
                    session["id"] = None
                    session["ts"] = None
                    return render_template(
                        "index.html",
                        auth_type=user.login_current_step,
                        error_msg="Invalid Login",
                    )

            elif user.login_current_step == "cc":
                signature = request.form.get("signature")
                check = False
                if signature:
                    check = user.is_challenge_signature_valid(signature)
                if not check:
                    user.login_current_step = levels[0]
                    current_context.login = 1
                    current_context.method = user.login_current_step
                    db.session.add(current_context)
                    db.session.commit()
                    session["id"] = None
                    session["ts"] = None
                    return render_template(
                        "index.html",
                        auth_type=user.login_current_step,
                        error_msg="Invalid Login",
                    )

            elif user.login_current_step == "invalid":
                current_context.login = 1
                current_context.method = user.login_current_step
                db.session.add(current_context)
                db.session.commit()
                return render_template(
                    "index.html",
                    auth_type=user.login_current_step,
                    error_msg="Invalid Login",
                )

            next_page_url: str = request.args.get("next")
            params = {
                "response_type": request.args.get("response_type"),
                "client_id": request.args.get("client_id"),
                "scope": request.args.get("scope"),
            }
            next_page: str = next_page_url + "?" + urllib.parse.urlencode(params)

            if (
                user.login_current_step in levels
                and Context.get_next_level(user.login_current_step, levels) == "in"
            ):
                user.login_current_step = levels[0]
                current_context.method = levels[0]
                current_context.user_id = user.id
                db.session.add(current_context)
                db.session.commit()
            else:
                current_context.method = user.login_current_step
                db.session.add(current_context)
                db.session.commit()

                user.login_current_step = (
                    "in"
                    if user.login_current_step
                    == Context.get_behavior(
                        request.args.get("client_id", None, type=str)
                    )
                    else Context.get_next_level(user.login_current_step, levels)
                )
                db.session.commit()
                return redirect(request.url) if next_page else redirect(f"/")

            if next_page:
                return redirect(next_page)

            return redirect("/")

        if user:
            if user.login_current_step == levels[0]:
                return render_template("index.html", user=user.email)
            if user.login_current_step == "cc":
                user.cc_challenge = base64.urlsafe_b64encode(
                    secrets.token_bytes(64)
                ).decode("utf-8")
                return render_template(
                    "index.html",
                    auth_type=user.login_current_step,
                    challenge=user.cc_challenge,
                    token=oauth.create_cc_token(user),
                )
            elif user.login_current_step == "eotp":
                user.gen_email_otp()

            return render_template("index.html", auth_type=user.login_current_step)
        else:
            return render_template("index.html", auth_type="password")
    except:
        traceback.print_exc()
        return render_template("index.html", error_msg="Internal Error"), 500


@bp.route("/oauth/authorize", methods=["GET", "POST"])
def authorize():
    try:
        user: User = current_user()
        if not user:
            return redirect(
                url_for("home.home", next=request.url.replace("?", "&"))
                .replace("%3D", "=")
                .replace("%26", "&")
            )

        if request.method == "GET":
            try:
                grant = authorization.get_consent_grant(end_user=user)
                grant_str = oauth.get_grant_params_str(grant)
                if grant_str:
                    grant = grant_str
            except OAuth2Error as error:
                return error.error
            return render_template("authorize.html", user=user, grant=grant)

        if not user and "username" in request.form:
            username = request.form.get("username")
            user = User.query.filter_by(username=username).first()
        if request.form["confirm"]:
            grant_user = user
        else:
            grant_user = None
        return authorization.create_authorization_response(grant_user=grant_user)
    except:
        traceback.print_exc()
        return render_template("index.html", error_msg="Internal Error"), 500


# provide an access token
@bp.route("/oauth/token", methods=["POST"])
def issue_token():
    try:
        return authorization.create_token_response()
    except:
        traceback.print_exc()
        return jsonify(success=False), 500


@bp.route("/register", methods=["POST", "GET"])
def register():
    try:
        auth = request.authorization

        if auth and auth.username and auth.password:
            client_id = auth.username
            client_secret = auth.password
            client = OAuth2Client.query.filter_by(
                client_id=client_id, client_secret=client_secret
            ).first()
            if (
                not client
                or not client.client_metadata.get("internal_authorization")
                or "create_clients"
                not in client.client_metadata.get("internal_authorization")
            ):
                return render_template("index.html", error_msg="Forbidden"), 403

        registration_code = request.args.get("id")

        if request.method == "GET":
            if registration_code:
                user = User.query.filter_by(registration_code=registration_code).first()
                client = OAuth2Client.query.filter_by(client_id=user.client_id).first()
                levels = json.loads(client.client_metadata["user_auth_method"])[
                    "levels"
                ]

                if len(levels) > 1:
                    levels.insert(
                        len(levels) - 1,
                        json.loads(client.client_metadata["user_auth_method"])[
                            "limit-condition"
                        ]["behavior"],
                    )
                else:
                    levels += [
                        json.loads(client.client_metadata["user_auth_method"])[
                            "limit-condition"
                        ]["behavior"],
                    ]
            else:
                return render_template("index.html", error_msg="Invalid Request"), 400

            if user.is_registered == 1:  # user already registered
                return render_template("index.html", error_msg="Invalid Request"), 400

            if not user:  # invalid registration code
                return render_template("index.html", error_msg="Internal Request"), 403

            if user.registration_current_step == "in":
                user.is_registered = 1
                db.session.commit()
                return render_template(
                    "register.html", auth_type="in", success_msg="Registration Finished"
                )

            if user.registration_current_step in ["eotp"]:
                user.registration_current_step = Context.get_next_level(
                    user.registration_current_step, levels
                )
                db.session.commit()
                return redirect(request.url)

            if user.registration_current_step == "totp":
                qr_code = user.get_totp_qr_code()
                return render_template(
                    "register.html",
                    qr_code=base64.b64encode(qr_code).decode("utf-8"),
                    auth_type="totp",
                )

            if user.registration_current_step == "hotp":
                qr_code = user.get_hotp_qr_code()
                return render_template(
                    "register.html",
                    qr_code=base64.b64encode(qr_code).decode("utf-8"),
                    auth_type="totp",
                )

            if user.registration_current_step == "cc":
                challenge = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode(
                    "utf-8"
                )
                user.cc_challenge = challenge
                db.session.commit()
                return render_template(
                    "register.html",
                    token=oauth.create_cc_token(user),
                    challenge=challenge,
                    auth_type="cc",
                )

            return render_template(
                "register.html",
                auth_type=user.registration_current_step,
            )

        if not registration_code:
            user = User(
                email=request.json["email"],
                role=request.json["role"],
                client_id=request.json["client_id"],
                registration_code=base64.urlsafe_b64encode(
                    secrets.token_bytes(32)
                ).decode("utf-8"),
                totp_secret=base64.b32encode(secrets.token_bytes(10)).decode("utf-8"),
            )
            user.send_registration_email(request.host)
            db.session.add(user)
            db.session.commit()
            return jsonify(success=True)

        user = User.query.filter_by(registration_code=registration_code).first()
        client = OAuth2Client.query.filter_by(client_id=user.client_id).first()
        levels = json.loads(client.client_metadata["user_auth_method"])["levels"]
        if len(levels) > 1:
            levels.insert(
                len(levels) - 1,
                json.loads(client.client_metadata["user_auth_method"])[
                    "limit-condition"
                ]["behavior"],
            )
        else:
            levels += [
                json.loads(client.client_metadata["user_auth_method"])[
                    "limit-condition"
                ]["behavior"],
            ]

        if user.registration_current_step == "password":
            password = request.form.get("password")
            if (
                len(password) < 12
                or not re.search(r"[a-zA-Z]+", password)
                or not re.search(r"[0-9]+", password)
            ):
                return render_template(
                    "register.html",
                    auth_type=user.registration_current_step,
                    error_msg="Password must have at least one number and one letter and be more than 12 characters long.",
                )
            user.password = User.gen_hash(password)
            user.registration_current_step = Context.get_next_level(
                user.registration_current_step, levels
            )
            db.session.commit()

        elif user.registration_current_step == "cc":
            cc_certificate = request.form.get("certificate")
            challenge_response = request.form.get("signature")
            if cc_certificate:
                user.cc_certificate = cc_certificate
                db.session.commit()
            else:
                user.registration_current_step = levels[0]
                db.session.commit()
                return (
                    render_template(
                        "register.html",
                        auth_type=user.registration_current_step,
                        error_msg="Error",
                    ),
                    400,
                )

            if not challenge_response or not user.is_challenge_signature_valid(
                challenge_response
            ):
                user.certificate = None
                user.registration_current_step = levels[0]
                db.session.commit()
                return (
                    render_template(
                        "register.html",
                        auth_type=user.registration_current_step,
                        error_msg="Invalid signature",
                    ),
                    403,
                )
            user.registration_current_step = Context.get_next_level(
                user.registration_current_step, levels
            )
            db.session.commit()
        else:
            user.registration_current_step = Context.get_next_level(
                user.registration_current_step, levels
            )
            db.session.commit()

        return redirect(request.url)
    except:
        traceback.print_exc()
        if request.method == "GET":
            return render_template("index.html", error_msg="Internal Error"), 400
        else:
            return jsonify(success=False), 500


@bp.route("/logout")
def logout():
    try:
        del session["id"]
        return redirect("/")
    except:
        return redirect("/", error_msg="Internal Error"), 500
