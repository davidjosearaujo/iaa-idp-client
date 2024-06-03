import base64
import secrets
from authlib.integrations.flask_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
)
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
    create_revocation_endpoint,
    create_bearer_token_validator,
)
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
import time
import jwt
from cryptography.hazmat.primitives import serialization
from models import db, User, OAuth2Client, OAuth2AuthorizationCode, OAuth2Token


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]

    def save_authorization_code(self, code, request):
        code_challenge = request.data.get("code_challenge")
        code_challenge_method = request.data.get("code_challenge_method")
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        auth_code = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id
        ).first()
        if auth_code and not auth_code.is_expired():
            return auth_code

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)

    def create_token_response(self):
        authorization_code = self.request.authorization_code
        include_refresh_token = self.request.data.get("include_refresh_token")

        user = self.authenticate_user(authorization_code)
        client = OAuth2Client.query.filter_by(
            client_id=authorization_code.client_id
        ).first()

        if not user or not client:
            raise super.InvalidGrantError("Invalid code.")
        self.request.user = user

        private_key = serialization.load_ssh_private_key(
            open("./idp_id_rsa", "r").read().encode(), password=b""
        )

        scope = authorization_code.get_scope()

        token = {
            "access_token": jwt.encode(
                {
                    "email": user.email,
                    "role": user.role,
                    "access_whitelist": client.client_metadata.get("authorization"),
                    "iat": int(time.time()),
                    "exp": int(time.time())
                    + client.client_metadata.get("token_lifetime"),
                },
                private_key,
                algorithm="RS256",
            ),
            "token_type": "JWT",
            "scope": scope,
            "expires_in": client.client_metadata.get("token_lifetime"),
        }

        if include_refresh_token:
            token["refresh_token"] = base64.urlsafe_b64encode(
                secrets.token_bytes(32)
            ).decode("utf-8")

        self.save_token(token)
        self.execute_hook("process_token", token=token)
        self.delete_authorization_code(authorization_code)
        return (
            200,
            (
                {
                    "token": token["access_token"],
                    "refresh_token": token["refresh_token"],
                    "token_type": "JWT",
                }
                if include_refresh_token
                else {"token": token["access_token"], "token_type": "JWT"}
            ),
            grants.BaseGrant.TOKEN_RESPONSE_HEADER,
        )


def create_save_token_func(session, token_model):
    def save_token(token, request):
        if request.user:
            user_id = request.user.get_user_id()
        else:
            user_id = None
        client = request.client
        item = token_model(client_id=client.client_id, user_id=user_id, **token)
        session.add(item)
        session.commit()

    return save_token


class RefreshTokenGrant(grants.RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        token = OAuth2Token.query.filter_by(refresh_token=refresh_token).first()
        if token.is_refresh_token_active():
            return token
        return None

    def create_access_token(self, token, client):
        user = User.query.get(token.user_id)
        private_key = serialization.load_ssh_private_key(
            open("./idp_id_rsa", "r").read().encode(), password=b""
        )

        access_token = jwt.encode(
            {
                "email": user.email,
                "role": user.role,
                "access_whitelist": client.client_metadata.get("authorization"),
                "iat": int(time.time()),
                "exp": int(time.time()) + client.client_metadata.get("token_lifetime"),
            },
            private_key,
            algorithm="RS256",
        )
        return access_token

    def save_bearer_token(self, token, request):
        item = OAuth2Token(
            client_id=request.client.client_id, user_id=request.user.id, **token
        )
        db.session.add(item)
        db.session.commit()

    def create_token_response(self):
        client = self.request.client
        token = self.request.refresh_token
        token.is_refresh_token_active()

        if token:
            access_token = self.create_access_token(token, client)

            bearer_token = {
                "access_token": access_token,
                "token_type": "JWT",
                "scope": token.scope,
                "expires_in": int(time.time())
                + client.client_metadata.get("token_lifetime"),
            }
            self.save_token(bearer_token)
            return (
                200,
                {"token": bearer_token["access_token"], "token_type": "JWT"},
                self.TOKEN_RESPONSE_HEADER,
            )
        return 400, {"error": "invalid_grant"}, self.TOKEN_RESPONSE_HEADER


query_client = create_query_client_func(db.session, OAuth2Client)
save_token = create_save_token_func(db.session, OAuth2Token)
authorization = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)
require_oauth = ResourceProtector()


def setup_oauth(app):
    authorization.init_app(app)

    authorization.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    authorization.register_grant(RefreshTokenGrant)

    # support revocation
    revocation_cls = create_revocation_endpoint(db.session, OAuth2Token)
    authorization.register_endpoint(revocation_cls)

    # protect resource
    bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())


def create_cc_token(user):
    private_key = serialization.load_ssh_private_key(
        open("./idp_id_rsa", "r").read().encode(), password=b""
    )
    cc_access_token = jwt.encode(
        {
            "email": user.email,
            "access_whitelist": ["cc"],
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
        },
        private_key,
        algorithm="RS256",
    )
    return cc_access_token


def get_grant_params_str(grant):
    grant_to_params = {'profile': 'profile - email'}
    return grant_to_params.get(grant)
