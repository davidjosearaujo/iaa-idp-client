from flask import Flask
import time
from werkzeug.security import gen_salt
from models import db, OAuth2Client
import yaml
import os
import sys
import json
import base64
import secrets

from models import db, User
from oauth import setup_oauth
from router import bp

app_config: dict = {
    "SECRET_KEY": os.environ["SECRET_KEY"],
    "OAUTH2_REFRESH_TOKEN_GENERATOR": True,
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    "SQLALCHEMY_DATABASE_URI": os.environ["SQLALCHEMY_DATABASE_URI"],
}

mandatory_client_config_keys: list = [
    "name",
    "uri",
    "redirect_uris",
    "auth",
    "authorization",
    "token_lifetime",
]

app: Flask = Flask(__name__)


def read_clients_config(configs_dir: str) -> dict:
    clients: list = []

    try:
        for filename in os.listdir(configs_dir):
            if os.path.isfile(os.path.join(configs_dir, filename)):
                try:
                    with open(os.path.join(configs_dir, filename), "r") as file:
                        client: dict = yaml.safe_load(file)
                    if all(key in client for key in mandatory_client_config_keys):
                        clients.append(client)
                    else:
                        print(
                            f"Invalid client configuration file: {filename}",
                            file=sys.stderr,
                        )
                except:
                    print(
                        f"Unable to read client configuration file: {filename}",
                        file=sys.stderr,
                    )

    except:
        print(
            f"Invalid clients configuration files directory: {filename}",
            file=sys.stderr,
        )

    return clients


def set_client(client_config: dict, client_id: str):
    client_id_issued_at: int = int(time.time())
    client: OAuth2Client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
    )

    client_config["auth"]["levels"].extend(["in"])

    client_metadata: dict = {
        "client_name": client_config["name"],
        "client_uri": client_config["uri"],
        "grant_types": [
            "authorization_code",
            "refresh_token",
        ],  # impose this flow -> 1. request auth code, 2. request access token
        "redirect_uris": client_config["redirect_uris"],
        "response_types": "code",
        "scope": "profile",
        "user_auth_method": json.dumps(client_config["auth"]),
        "token_endpoint_auth_method": "client_secret_basic",
        "authorization": client_config["authorization"],
        "internal_authorization": client_config.get("internal_authorization"),
        "token_lifetime": client_config["token_lifetime"],
    }
    client.set_client_metadata(client_metadata)

    client.client_secret = client_config["client_secret"]

    db.session.add(client)
    db.session.commit()


def setup_database(app: Flask) -> None:
    db.init_app(app)
    with app.app_context():
        if not os.path.exists("instance/db.sqlite"):
            db.create_all()
            registration_code = [
                base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8")
                for i in range(3)
            ]
            totp_secret = [
                base64.b32encode(secrets.token_bytes(10)).decode("utf-8")
                for i in range(3)
            ]

            dummy_users = [
                {
                    "email": f"{os.environ.get('CLIENT_EMAIL')}",
                    "role": "client",
                    "registration_code": registration_code[0],
                    "totp_secret": totp_secret[0],
                    "client_id": "aaaaaaaaaaaaaaaaaaaaaaaa",
                },
                {
                    "email": f"{os.environ.get('OFFICER_EMAIL')}",
                    "role": "officer",
                    "registration_code": registration_code[1],
                    "totp_secret": totp_secret[1],
                    "client_id": "bbbbbbbbbbbbbbbbbbbbbbbb",
                },
                {
                    "email": f"{os.environ.get('MANAGER_EMAIL')}",
                    "role": "manager",
                    "registration_code": registration_code[2],
                    "totp_secret": totp_secret[2],
                    "client_id": "cccccccccccccccccccccccc",
                },
            ]
            for user_data in dummy_users:
                user = User(**user_data)
                user.send_registration_email("127.0.0.1:5000")
                db.session.add(user)
            db.session.commit()

            print("Please end the registration of the base users:")
            print(f"http://127.0.0.1:5000/register?id={registration_code[0]}")


def setup_oauth_clients(clients: list) -> None:
    for client in clients:
        set_client(client, client.get("client_id"))


if __name__ == "__main__":
    # Flask config
    if "WEBSITE_CONF" in os.environ:
        app.config.from_envvar("WEBSITE_CONF")

    if app_config is not None:
        if isinstance(app_config, dict):
            app.config.update(app_config)
        elif app_config.endswith(".py"):
            app.config.from_pyfile(app_config)

    # setup database and oauth
    setup_oauth(app)
    setup_database(app)

    if len(sys.argv) == 2 and sys.argv[1] == "LOAD_CLIENTS":
        clients: dict = read_clients_config("clients")
        with app.app_context():
            setup_oauth_clients(clients)

    # start server
    app.register_blueprint(bp, url_prefix="")
    app.run(debug=False, host="0.0.0.0", port=5000)
