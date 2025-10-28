from cachetools import FIFOCache
from datetime import datetime
from flask import Flask
from logging import Logger
from pypomes_core import (
    APP_PREFIX, TZ_LOCAL, env_get_int, env_get_str
)
from typing import Any, Final

from .common_pomes import _service_token, _get_user_data

JUSBR_CLIENT_ID: Final[str] = env_get_str(key=f"{APP_PREFIX}_JUSBR_CLIENT_ID")
JUSBR_CLIENT_SECRET: Final[str] = env_get_str(key=f"{APP_PREFIX}_JUSBR_CLIENT_SECRET")
JUSBR_CLIENT_TIMEOUT: Final[int] = env_get_int(key=f"{APP_PREFIX}_JUSBR_CLIENT_TIMEOUT")

JUSBR_ENDPOINT_CALLBACK: Final[str] = env_get_str(key=f"{APP_PREFIX}_JUSBR_ENDPOINT_CALLBACK",
                                                  def_value="/iam/jusbr:callback")
JUSBR_ENDPOINT_LOGIN: Final[str] = env_get_str(key=f"{APP_PREFIX}_JUSBR_ENDPOINT_LOGIN",
                                               def_value="/iam/jusbr:login")
JUSBR_ENDPOINT_LOGOUT: Final[str] = env_get_str(key=f"{APP_PREFIX}_JUSBR_ENDPOINT_LOGOUT",
                                                def_value="/iam/jusbr:logout")
JUSBR_ENDPOINT_TOKEN: Final[str] = env_get_str(key=f"{APP_PREFIX}_JUSBR_ENDPOINT_TOKEN",
                                               def_value="/iam/jusbr:get-token")

JUSBR_PUBLIC_KEY_LIFETIME: Final[int] = env_get_int(key=f"{APP_PREFIX}_JUSBR_PUBLIC_KEY_LIFETIME",
                                                    def_value=86400)  # 24 hours
JUSBR_URL_AUTH_BASE: Final[str] = env_get_str(key=f"{APP_PREFIX}_JUSBR_URL_AUTH_BASE")
JUSBR_URL_AUTH_CALLBACK: Final[str] = env_get_str(key=f"{APP_PREFIX}_JUSBR_URL_AUTH_CALLBACK")

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
#    "cache-obj": <FIFOCache>
# }
# data in "cache-obj":
# {
#    "users": {
#       "<user-id>": {
#         "access-token": <str>
#         "refresh-token": <str>
#         "access-expiration": <timestamp>,
#         "login-expiration": <timestamp>,   <-- transient
#         "login-id": <str>,                 <-- transient
#         "oauth-scope": <str>               <-- optional
#       }
#    }
# }
_jusbr_registry: dict[str, Any] | None = None

# dafault logger
_jusbr_logger: Logger | None = None


def jusbr_setup(flask_app: Flask,
                client_id: str = JUSBR_CLIENT_ID,
                client_secret: str = JUSBR_CLIENT_SECRET,
                client_timeout: int = JUSBR_CLIENT_TIMEOUT,
                public_key_lifetime: int = JUSBR_PUBLIC_KEY_LIFETIME,
                callback_endpoint: str = JUSBR_ENDPOINT_CALLBACK,
                token_endpoint: str = JUSBR_ENDPOINT_TOKEN,
                login_endpoint: str = JUSBR_ENDPOINT_LOGIN,
                logout_endpoint: str = JUSBR_ENDPOINT_LOGOUT,
                base_url: str = JUSBR_URL_AUTH_BASE,
                callback_url: str = JUSBR_URL_AUTH_CALLBACK,
                logger: Logger = None) -> None:
    """
    Configure the JusBR IAM.

    This should be invoked only once, before the first access to a JusBR service.

    :param flask_app: the Flask application
    :param client_id: the client's identification with JusBR
    :param client_secret: the client's password with JusBR
    :param client_timeout: timeout for login authentication (in seconds,defaults to no timeout)
    :param public_key_lifetime: how long to use JusBR's public key, before refreshing it (in seconds)
    :param callback_endpoint: endpoint for the callback from JusBR
    :param token_endpoint: endpoint for retrieving the JusBR authentication token
    :param login_endpoint: endpoint for redirecting user to JusBR login page
    :param logout_endpoint: endpoint for terminating user access to JusBR
    :param base_url: base URL to request the JusBR services
    :param callback_url: URL for JusBR to callback on login
    :param logger: optional logger
    """
    from .iam_pomes import service_login, service_logout, service_callback, service_token
    global _jusbr_logger, _jusbr_registry

    # establish the logger
    _logger = logger

    # configure the JusBR registry
    _jusbr_registry = {
        "client-id": client_id,
        "client-secret": client_secret,
        "client-timeout": client_timeout,
        "base-url": base_url,
        "callback-url": callback_url,
        "key-expiration": int(datetime.now(tz=TZ_LOCAL).timestamp()),
        "key-lifetime": public_key_lifetime,
        "cache-obj": FIFOCache(maxsize=1048576)
    }

    # establish the endpoints
    if login_endpoint:
        flask_app.add_url_rule(rule=login_endpoint,
                               endpoint="jusbr-login",
                               view_func=service_login,
                               methods=["GET"])
    if logout_endpoint:
        flask_app.add_url_rule(rule=logout_endpoint,
                               endpoint="jusbr-logout",
                               view_func=service_logout,
                               methods=["GET"])
    if callback_endpoint:
        flask_app.add_url_rule(rule=callback_endpoint,
                               endpoint="jusbr-callback",
                               view_func=service_callback,
                               methods=["GET", "POST"])
    if token_endpoint:
        flask_app.add_url_rule(rule=token_endpoint,
                               endpoint="jusbr-token",
                               view_func=service_token,
                               methods=["GET"])


def jusbr_get_token(user_id: str,
                    errors: list[str] = None,
                    logger: Logger = None) -> str:
    """
    Retrieve a JusBR authentication token for *user_id*.

    :param user_id: the user's identification
    :param errors: incidental errors
    :param logger: optional logger
    :return: the uthentication tokem
    """
    global _jusbr_registry

    # retrieve the token
    args: dict[str, Any] = {"user-id": user_id}
    return _service_token(registry=_jusbr_registry,
                          args=args,
                          errors=errors,
                          logger=logger)


def jusbr_set_scope(user_id: str,
                    scope: str,
                    logger: Logger = None) -> None:
    """
    Set the OAuth2 scope of *user_id* to *scope*.

    :param user_id: the user's identification
    :param scope: the OAuth2 scope to set to the user
    :param logger: optional logger
    """
    global _jusbr_registry

    # retrieve user data
    user_data: dict[str, Any] = _get_user_data(registry=_jusbr_registry,
                                               user_id=user_id,
                                               logger=logger)
    # set the OAuth2 scope
    user_data["oauth-scope"] = scope
    if logger:
        logger.debug(msg=f"Scope for user '{user_id}' set to '{scope}'")
