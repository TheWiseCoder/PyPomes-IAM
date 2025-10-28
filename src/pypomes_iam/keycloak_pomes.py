from cachetools import FIFOCache
from datetime import datetime
from flask import Flask
from logging import Logger
from pypomes_core import (
    APP_PREFIX, TZ_LOCAL, env_get_int, env_get_str
)
from typing import Any, Final

from .common_pomes import _service_token

KEYCLOAK_CLIENT_ID: Final[str] = env_get_str(key=f"{APP_PREFIX}_KEYCLOAK_CLIENT_ID")
KEYCLOAK_CLIENT_SECRET: Final[str] = env_get_str(key=f"{APP_PREFIX}_KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_CLIENT_TIMEOUT: Final[int] = env_get_int(key=f"{APP_PREFIX}_KEYCLOAK_CLIENT_TIMEOUT")

KEYCLOAK_ENDPOINT_CALLBACK: Final[str] = env_get_str(key=f"{APP_PREFIX}_KEYCLOAK_ENDPOINT_CALLBACK",
                                                     def_value="/iam/keycloak:callback")
KEYCLOAK_ENDPOINT_LOGIN: Final[str] = env_get_str(key=f"{APP_PREFIX}_KEYCLOAK_ENDPOINT_LOGIN",
                                                  def_value="/iam/keycloak:login")
KEYCLOAK_ENDPOINT_LOGOUT: Final[str] = env_get_str(key=f"{APP_PREFIX}_KEYCLOAK_ENDPOINT_LOGOUT",
                                                   def_value="/iam/keycloak:logout")
KEYCLOAK_ENDPOINT_TOKEN: Final[str] = env_get_str(key=f"{APP_PREFIX}_KEYCLOAK_ENDPOINT_TOKEN",
                                                  def_value="/iam/keycloak:get-token")

KEYCLOAK_PUBLIC_KEY_LIFETIME: Final[int] = env_get_int(key=f"{APP_PREFIX}_KEYCLOAK_PUBLIC_KEY_LIFETIME",
                                                       def_value=86400)  # 24 hours
KEYCLOAK_REALM: Final[str] = env_get_str(key=f"{APP_PREFIX}_KEYCLOAK_REALM")
KEYCLOAK_URL_AUTH_BASE: Final[str] = env_get_str(key=f"{APP_PREFIX}_KEYCLOAK_URL_AUTH_BASE")
KEYCLOAK_URL_AUTH_CALLBACK: Final[str] = env_get_str(key=f"{APP_PREFIX}_KEYCLOAK_URL_AUTH_CALLBACK")

# registry structure:
# {
#    "client-id": <str>,
#    "client-secret": <str>,
#    "client-timeout": <int>,
#    "public_key": <str>,
#    "key-lifetime": <int>,
#    "key-expiration": <int>,
#    "base-url": <str>,
#    "callback-url": <str>,
#    "safe-cache": <FIFOCache>
# }
# data in "safe-cache":
# {
#    "users": {
#       "<user-id>": {
#         "access-token": <str>
#         "refresh-token": <str>
#         "access-expiration": <timestamp>,
#         "login-expiration": <timestamp>,   <-- transient
#         "login-id": <str>,                 <-- transient
#       }
#    }
# }
_keycloak_registry: dict[str, Any] = {}

# dafault logger
_keycloak_logger: Logger | None = None


def keycloak_setup(flask_app: Flask,
                   client_id: str = KEYCLOAK_CLIENT_ID,
                   client_secret: str = KEYCLOAK_CLIENT_SECRET,
                   client_timeout: int = KEYCLOAK_CLIENT_TIMEOUT,
                   public_key_lifetime: int = KEYCLOAK_PUBLIC_KEY_LIFETIME,
                   realm: str = KEYCLOAK_REALM,
                   callback_endpoint: str = KEYCLOAK_ENDPOINT_CALLBACK,
                   token_endpoint: str = KEYCLOAK_ENDPOINT_TOKEN,
                   login_endpoint: str = KEYCLOAK_ENDPOINT_LOGIN,
                   logout_endpoint: str = KEYCLOAK_ENDPOINT_LOGOUT,
                   base_url: str = KEYCLOAK_URL_AUTH_BASE,
                   callback_url: str = KEYCLOAK_URL_AUTH_CALLBACK,
                   logger: Logger = None) -> None:
    """
    Configure the Keycloak IAM.

    This should be invoked only once, before the first access to a Keycloak service.

    :param flask_app: the Flask application
    :param client_id: the client's identification with JusBR
    :param client_secret: the client's password with JusBR
    :param client_timeout: timeout for login authentication (in seconds,defaults to no timeout)
    :param public_key_lifetime: how long to use Keycloak's public key, before refreshing it (in seconds)
    :param realm: the Keycloak realm
    :param callback_endpoint: endpoint for the callback from JusBR
    :param token_endpoint: endpoint for retrieving the JusBR authentication token
    :param login_endpoint: endpoint for redirecting user to JusBR login page
    :param logout_endpoint: endpoint for terminating user access to JusBR
    :param base_url: base URL to request the JusBR services
    :param callback_url: URL for Keycloak to callback on login
    :param logger: optional logger
    """
    from .iam_pomes import service_login, service_logout, service_callback, service_token
    global _keycloak_logger, _keycloak_registry

    # establish the logger
    _keycloak_logger = logger

    # configure the JusBR registry
    _keycloak_registry = {
        "client-id": client_id,
        "client-secret": client_secret,
        "client-timeout": client_timeout,
        "base-url": f"{base_url}/realms/{realm}",
        "callback-url": callback_url,
        "key-expiration": int(datetime.now(tz=TZ_LOCAL).timestamp()),
        "key-lifetime": public_key_lifetime,
        "safe-cache": FIFOCache(maxsize=1048576)
    }

    # establish the endpoints
    if token_endpoint:
        flask_app.add_url_rule(rule=token_endpoint,
                               endpoint="keycloak-token",
                               view_func=service_token,
                               methods=["GET"])
    if login_endpoint:
        flask_app.add_url_rule(rule=login_endpoint,
                               endpoint="keycloak-login",
                               view_func=service_login,
                               methods=["GET"])
    if logout_endpoint:
        flask_app.add_url_rule(rule=logout_endpoint,
                               endpoint="keycloak-logout",
                               view_func=service_logout,
                               methods=["GET"])
    if callback_endpoint:
        flask_app.add_url_rule(rule=callback_endpoint,
                               endpoint="keycloak-callback",
                               view_func=service_callback,
                               methods=["POST"])


def keycloak_get_token(user_id: str,
                       errors: list[str] = None,
                       logger: Logger = None) -> str:
    """
    Retrieve a Keycloak authentication token for *user_id*.

    :param user_id: the user's identification
    :param errors: incidental errors
    :param logger: optional logger
    :return: the uthentication tokem
    """
    global _keycloak_registry

    # retrieve the token
    args: dict[str, Any] = {"user-id": user_id}
    return _service_token(registry=_keycloak_registry,
                          args=args,
                          errors=errors,
                          logger=logger)
