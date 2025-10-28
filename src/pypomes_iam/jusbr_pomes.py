from cachetools import FIFOCache
from datetime import datetime
from flask import Flask, Response, redirect, request, jsonify
from logging import Logger
from pypomes_core import (
    APP_PREFIX, TZ_LOCAL, env_get_int, env_get_str
)
from typing import Any, Final

from .common_pomes import (
    _service_login, _service_logout,
    _service_callback, _service_token,
    _get_user_data, _log_init
)

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
_logger: Logger | None = None


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
    # establish the logger
    global _logger
    _logger = logger

    # configure the JusBR registry
    global _jusbr_registry
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
    if token_endpoint:
        flask_app.add_url_rule(rule=token_endpoint,
                               endpoint="jusbr-token",
                               view_func=service_token,
                               methods=["GET"])
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


# @flask_app.route(rule=<login_endpoint>,  # JUSBR_LOGIN_ENDPOINT: /iam/jusbr:login
#                  methods=["GET"])
def service_login() -> Response:
    """
    Entry point for the JusBR login service.

    Redirect the request to the JusBR authentication page, with the appropriate parameters.

    :return: the response from the redirect operation
    """
    global _jusbr_registry

    # log the request
    if _logger:
        _logger.debug(msg=_log_init(request=request))

    # obtain the redirect URL
    auth_url: str = _service_login(registry=_jusbr_registry,
                                   args=request.args,
                                   logger=_logger)
    # redirect the request
    result: Response = redirect(location=auth_url)

    # log the response
    if _logger:
        _logger.debug(msg=f"Response {result}")

    return result


# @flask_app.route(rule=<login_endpoint>,  # JUSBR_LOGIN_ENDPOINT: /iam/jusbr:logout
#                  methods=["GET"])
def service_logout() -> Response:
    """
    Entry point for the JusBR logout service.

    Remove all data associating the user with JusBR from the registry.

    :return: response *OK*
    """
    global _jusbr_registry

    # log the request
    if _logger:
        _logger.debug(msg=_log_init(request=request))

    # logout the user
    _service_logout(registry=_jusbr_registry,
                    args=request.args,
                    logger=_logger)

    result: Response = Response(status=200)

    # log the response
    if _logger:
        _logger.debug(msg=f"Response {result}")

    return result


# @flask_app.route(rule=<callback_endpoint>,  # JUSBR_CALLBACK_ENDPOINT: /iam/jusbr:callback
#                  methods=["GET", "POST"])
def service_callback() -> Response:
    """
    Entry point for the callback from JusBR on authentication operation.

    :return: the response containing the token, or *BAD REQUEST*
    """
    global _jusbr_registry

    # log the request
    if _logger:
        _logger.debug(msg=_log_init(request=request))

    # process the callback operation
    errors: list[str] = []
    token_data: tuple[str, str] = _service_callback(registry=_jusbr_registry,
                                                    args=request.args,
                                                    errors=errors,
                                                    logger=_logger)
    result: Response
    if errors:
        result = jsonify({"errors": "; ".join(errors)})
        result.status_code = 400
    else:
        result = jsonify({
            "user_id": token_data[0],
            "access_token": token_data[1]})

    # log the response
    if _logger:
        _logger.debug(msg=f"Response {result}")

    return result


# @flask_app.route(rule=<token_endpoint>,  # JUSBR_TOKEN_ENDPOINT: /iam/jusbr:get-token
#                  methods=["GET"])
def service_token() -> Response:
    """
    Entry point for retrieving the JusBR token.

    :return: the response containing the token, or *UNAUTHORIZED*
    """
    global _jusbr_registry

    # log the request
    if _logger:
        _logger.debug(msg=_log_init(request=request))

    # retrieve the token
    errors: list[str] = []
    token: str = _service_token(registry=_jusbr_registry,
                                args=request.args,
                                errors=errors,
                                logger=_logger)
    result: Response
    if token:
        result = jsonify({"token": token})
    else:
        result = Response("; ".join(errors))
        result.status_code = 401

    # log the response
    if _logger:
        _logger.debug(msg=f"Response {result}")

    return result


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
