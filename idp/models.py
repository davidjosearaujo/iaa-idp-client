import datetime
import json
import time
import hashlib
import base64
import random
from io import BytesIO
import pyqrcode
import onetimepass as otp
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.backends import default_backend
import sys

from mail import IdP_email

db = SQLAlchemy()
mail = IdP_email()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(40), unique=True)
    role = db.Column(db.String(32), default="client", nullable=False)
    password = db.Column(db.String(40))
    client_id = db.Column(db.String(50))
    login_current_step = db.Column(db.String(10), default="password")
    totp_secret = db.Column(db.String(16))
    hotp_last_counter = db.Column(db.Integer, default=1)
    is_registered = db.Column(db.Integer, default=0)
    registration_code = db.Column(db.String(32))
    registration_current_step = db.Column(db.String(10), default="password")
    cc_certificate = db.Column(db.String(5888))
    cc_challenge = db.Column(db.String(128))

    def __str__(self):
        return self.email

    def get_user_id(self):
        return self.id

    # maybe we can use a dynamic counter value
    def get_totp_uri(self):
        return f"otpauth://totp/IdpIaa:{self.email}?secret={self.totp_secret}&issuer=IdpIaa"

    def get_hotp_uri(self):
        return f"otpauth://hotp/IdpIaa:{self.email}?secret={self.totp_secret}&issuer=IdpIaa&counter=2"

    def get_totp_qr_code(self):
        url = pyqrcode.create(self.get_totp_uri())
        stream = BytesIO()
        url.svg(stream, scale=5)
        return stream.getvalue()

    def get_hotp_qr_code(self):
        url = pyqrcode.create(self.get_hotp_uri())
        stream = BytesIO()
        url.svg(stream, scale=5)
        return stream.getvalue()

    def check_totp(self, token):
        return otp.valid_totp(token, self.totp_secret)

    def check_hotp(self, token):
        last = otp.valid_hotp(token, self.totp_secret, last=self.hotp_last_counter)
        if last:
            self.hotp_last_counter = last
            db.session.commit()
            return True
        return False

    def check_password(self, password: str):
        return (
            base64.b64encode(hashlib.sha256(password.encode()).digest()).decode(
                encoding="utf-8"
            )
            == self.password
        )

    def gen_email_otp(self):
        otc = random.randint(100000, 999999)
        new_otc = OTP(otc=otc, issued_at=int(time.time()), user_id=self.id)

        mail.send_otp(otc, self.email)

        db.session.add(new_otc)
        db.session.commit()
        return new_otc.id

    def send_registration_email(self, host: str):
        mail.send_registration_link(
            f"http://{host}/register?id={self.registration_code}", self.email
        )

    def is_challenge_signature_valid(self, signature: str):
        ce = bytes.fromhex(self.cc_certificate)
        cert = x509.load_der_x509_certificate(ce, backend=default_backend())
        public_key = cert.public_key()
        sig = bytes.fromhex(signature)

        with open(
            f"cc_certs/{cert.issuer.rfc4514_string().split(',')[0][3:].replace(' ', '-').replace('ã', 'a').replace('ç', 'c')}.cer",
            "rb",
        ) as f:
            issuer_cert = x509.load_der_x509_certificate(
                f.read(), backend=default_backend()
            )
            issuer_public_key = issuer_cert.public_key()
            issuer_public_key.verify(
                cert.signature, cert.tbs_certificate_bytes, PKCS1v15(), hashes.SHA256()
            )
        try:
            public_key.verify(
                sig,
                bytes(self.cc_challenge, sys.getdefaultencoding()),
                PKCS1v15(),
                hashes.SHA1(),
            )
            return True
        except Exception:
            return False

    @staticmethod
    def gen_hash(password: str):
        return base64.b64encode(hashlib.sha256(password.encode()).digest()).decode(
            encoding="utf-8"
        )


class OAuth2Client(db.Model, OAuth2ClientMixin):
    __tablename__ = "oauth2_client"

    id = db.Column(db.Integer, primary_key=True)


class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = "oauth2_code"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")


class OAuth2Token(db.Model, OAuth2TokenMixin):
    __tablename__ = "oauth2_token"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")

    def is_refresh_token_active(self):
        expires_at = self.issued_at + self.expires_in + self.expires_in / 10
        return expires_at >= time.time()


class OTP(db.Model):
    __tablename__ = "otc"

    id = db.Column(db.Integer, primary_key=True)
    otc = db.Column(db.String(6))
    issued_at = db.Column(db.Integer)
    ttl = db.Column(db.Integer, default=60 * 5)  # in seconds (5 min default)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")
    used = db.Column(db.Integer, default=0)

    @staticmethod
    def verify_otp(user_id: int, otc: str):
        latest_otc = (
            OTP.query.filter(
                OTP.user_id == user_id,
                OTP.used == 0,
                OTP.issued_at + OTP.ttl
                >= int(time.time()),  # Filter for non-expired OTCs
            )
            .order_by(OTP.issued_at.desc())
            .first()
        )

        if not latest_otc:
            return False

        latest_otc.used = 1
        db.session.commit()

        return latest_otc.otc == otc


class Context(db.Model):
    __tablename__ = "context"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User")
    timestamp = db.Column(db.Float, default=int(time.time()))

    ip = db.Column(db.String(15))  # IP from where it connected
    login = db.Column(db.Integer, default=0)  # Login status (successful or failed)
    method = db.Column(
        db.String(10), default="password"
    )  # Authenticated method: password, email otp, hotp, eotp, in

    def __str__(self):
        return ",".join(
            [
                str(self.user_id),
                str(self.timestamp),
                self.ip,
                str(self.login),
                self.method,
            ]
        )

    @staticmethod
    def get_next_level(login_current_step, levels):
        return levels[(levels.index(login_current_step) + 1) % len(levels)]

    @staticmethod
    def get_behavior(client_id: str):
        client = OAuth2Client.query.filter(OAuth2Client.client_id == client_id).first()
        return json.loads(client.client_metadata["user_auth_method"])[
            "limit-condition"
        ]["behavior"]

    @staticmethod
    def get_levels(user: User, current_ip: str, client_id: str):
        # Get client authentication information
        client = OAuth2Client.query.filter(OAuth2Client.client_id == client_id).first()
        levels = json.loads(client.client_metadata["user_auth_method"])["levels"]
        conditions = json.loads(client.client_metadata["user_auth_method"])[
            "limit-condition"
        ]

        if not user:
            return levels

        if user.login_current_step == "in":
            user.login_current_step = levels[0]
            db.session.commit()
            return levels

        known_ips = (
            Context.query.filter(
                (Context.user_id == User.id) | (Context.user_id == None)
            )
            .with_entities(Context.ip)
            .distinct(Context.ip)
            .all()
        )

        if current_ip not in known_ips and user.login_current_step == "in":
            user.login_current_step = conditions["behavior"]
            db.session.commit()
            return levels

        flow = getattr(Context, user.role + "_flow")
        flow(user, conditions)

        return levels

    # If amount of failed logins exceeds the set limit,
    @staticmethod
    def client_flow(user, conditions):
        amount_failed = (
            Context.query.filter(
                Context.user_id == User.id,
                Context.timestamp
                > datetime.datetime.now() - datetime.timedelta(days=1),
            )
            .with_entities(getattr(Context, conditions["key"]))
            .count()
        )
        if amount_failed > conditions["limit"]:
            user.login_current_step = conditions["behavior"]
            db.session.commit()

    # If cc has not been used in more than the set period of time, it will be asked next step
    # If it is a weekend, it will be invalid
    @staticmethod
    def officer_flow(user, conditions):
        # Is weekend
        if datetime.datetime.today().weekday() >= 5:
            user.login_current_step = "invalid"
            db.session.commit()
            return

        amount_key_pass_week = (
            Context.query.filter(
                Context.user_id == User.id,
                Context.method == conditions["key"],
                Context.timestamp
                > datetime.datetime.now()
                - eval("datetime.timedelta(" + conditions["limit"] + ")"),
            )
            .with_entities(Context.method)
            .count()
        )

        amount_key_total = (
            Context.query.filter(
                Context.user_id == User.id,
                Context.method == conditions["key"],
            )
            .with_entities(Context.method)
            .count()
        )

        if amount_key_pass_week == 0 and amount_key_total > 0:
            user.login_current_step = conditions["behavior"]
            db.session.commit()

    @staticmethod
    def manager_flow(user, conditions):
        # Is weekend or after 7pm or before 7 am
        if (
            datetime.datetime.today().weekday() >= 5
            or (datetime.time(19, 0) <= datetime.datetime.now().time())
            or (datetime.datetime.now().time() <= datetime.time(7, 0))
        ):
            user.login_current_step = "invalid"
            db.session.commit()
            return

        amount_key_has_failed = (
            Context.query.filter(
                Context.user_id == User.id,
                Context.method == conditions["key"],
                Context.timestamp
                > datetime.datetime.now()
                - eval("datetime.timedelta(" + conditions["limit"] + ")"),
            )
            .with_entities(Context.method)
            .count()
        )

        amount_key_total = (
            Context.query.filter(
                Context.user_id == User.id,
                Context.method == conditions["key"],
            )
            .with_entities(Context.method)
            .count()
        )

        if amount_key_has_failed > 1 and amount_key_total > 0:
            user.login_current_step = conditions["behavior"]
            db.session.commit()
