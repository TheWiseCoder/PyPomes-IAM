import requests
import secrets
import string
import sys
from cachetools import Cache, FIFOCache, TTLCache
from datetime import datetime
from flask import Flask, Response, redirect, request, jsonify
from logging import Logger
from pypomes_core import (
    APP_PREFIX, TZ_LOCAL, env_get_int, env_get_str, exc_format
)
from typing import Any, Final

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

JUSBR_URL_AUTH_CALLBACK: Final[str] = env_get_str(key=f"{APP_PREFIX}_JUSBR_URL_AUTH_CALLBACK")
JUSBR_URL_AUTH_LOGIN: Final[str] = env_get_str(key=f"{APP_PREFIX}JUSBR_URL_AUTH_LOGIN")
JUSBR_URL_AUTH_TOKEN: Final[str] = env_get_str(key=f"{APP_PREFIX}JUSBR_URL_AUTH_TOKEN")

# safe memory cache - structure:
# {
#    "client-id": <str>,
#    "client-secret": <str>,
#    "auth-url": <str>,
#    "token-url": <str>,
#    "client-timeout": <int>,
#    "users": {
#       "<user-id>": {
#         "cache-obj": <Cache>,
#         "oauth-scope": <str>,
#         "access-expiration": <timestamp>,
#         data in <TTLCache>:
#           "oauth-state": <str>
#           "access-token": <str>
#           "refresh-token": <str>
#       }
#    }
# }
_jusbr_registry: dict[str, Any] = {
    "client-id": None,
    "client-secret": None,
    "client-timeout": None,
    "auth-url": None,
    "callback-url": None,
    "token-url": None,
    "users": {}
}

# dafault logger
_logger: Logger | None = None


def jusbr_setup(flask_app: Flask,
                client_id: str = JUSBR_CLIENT_ID,
                client_secret: str = JUSBR_CLIENT_SECRET,
                client_timeout: int = JUSBR_CLIENT_TIMEOUT,
                callback_endpoint: str = JUSBR_ENDPOINT_CALLBACK,
                token_endpoint: str = JUSBR_ENDPOINT_TOKEN,
                login_endpoint: str = JUSBR_ENDPOINT_LOGIN,
                logout_endpoint: str = JUSBR_ENDPOINT_LOGOUT,
                auth_url: str = JUSBR_URL_AUTH_LOGIN,
                callback_url: str = JUSBR_URL_AUTH_CALLBACK,
                token_url: str = JUSBR_URL_AUTH_TOKEN,
                logger: Logger = None) -> None:
    """
    Configure the JusBR IAM.

    This should be invoked only once, before the first access to a JusBR service.

    :param flask_app: the Flask application
    :param client_id: the client's identification with JusBR
    :param client_secret: the client's password with JusBR
    :param client_timeout: timeout for login authentication (in seconds,defaults to no timeout)
    :param callback_endpoint: endpoint for the callback from JusBR
    :param token_endpoint: endpoint for retrieving the JusBR authentication token
    :param login_endpoint: endpoint for redirecting user to JusBR login page
    :param logout_endpoint: endpoint for terminating user access to JusBR
    :param auth_url: URL to access the JusBR login page
    :param callback_url: URL for JusBR to callback on login
    :param token_url: URL for obtaing or refreshing the token
    :param logger: optional logger
    """
    # establish the logger
    global _logger
    _logger = logger

    # configure the JusBR registry
    global _jusbr_registry  # noqa: PLW0602
    _jusbr_registry.update({
        "client-id": client_id,
        "client-secret": client_secret,
        "client-timeout": client_timeout,
        "auth-url": auth_url,
        "callback-url": callback_url,
        "token-url": token_url
    })

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
                               methods=["POST"])


# @flask_app.route(rule=<login_endpoint>,  # JUSBR_LOGIN_ENDPOINT: /iam/jusbr:login
#                  methods=["GET"])
def service_login() -> Response:
    """
    Entry point for the JusBR login service.

    Redirect the request to the JusBR authentication page, with the apprpriate parameters.

    :return: the response from the redirect operation
    """
    global _jusbr_registry

    # retrieve user id
    input_params: dict[str, Any] = request.values
    user_id: str = input_params.get("user-id") or input_params.get("login")

    # retrieve user data
    user_data: dict[str, Any] = __get_user_data(user_id=user_id,
                                                logger=_logger)
    # build redirect url
    oauth_state: str = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    timeout: int = __get_login_timeout()
    safe_cache: Cache
    if timeout:
        safe_cache = TTLCache(maxsize=16,
                              ttl=600)
    else:
        safe_cache = FIFOCache(maxsize=16)
    safe_cache["oauth-state"] = oauth_state
    user_data["cache-obj"] = safe_cache
    auth_url: str = (f"{_jusbr_registry["auth-url"]}?response_type=code"
                     f"&client_id={_jusbr_registry["client-id"]}"
                     f"&redirect_url={_jusbr_registry["callback-url"]}"
                     f"&state={oauth_state}")
    if user_data.get("oauth-scope"):
        auth_url += f"&scope={user_data.get("oauth-scope")}"

    # redirect request
    return redirect(location=auth_url)


# @flask_app.route(rule=<login_endpoint>,  # JUSBR_LOGIN_ENDPOINT: /iam/jusbr:logout
#                  methods=["GET"])
def service_logout() -> Response:
    """
    Entry point for the JusBR logout service.

    Remove all data associating the user with JusBR from the registry.

    :return: the response from the redirect operation
    """
    global _jusbr_registry

    # retrieve user id
    input_params: dict[str, Any] = request.args
    user_id: str = input_params.get("user-id") or input_params.get("login")

    # remove user data
    if user_id in _jusbr_registry.get("users"):
        _jusbr_registry["users"].pop(user_id)
        if _logger:
            _logger.debug(f"User '{user_id}' removed from the registry")

    return Response(status=200)


# @flask_app.route(rule=<callback_endpoint>,  # JUSBR_CALLBACK_ENDPOINT: /iam/jusbr:callback
#                  methods=["POST"])
def service_callback() -> Response:
    """
    Entry point for the callback from JusBR on authentication operation.

    :return: the response containing the token, or *NOT AUTHORIZED*
    """
    global _jusbr_registry

    # validate the OAuth2 state
    oauth_state: str = request.args.get("state")
    user_data: dict[str, Any] | None = None
    if oauth_state:
        for data in _jusbr_registry.get("users"):
            safe_cache: Cache = user_data.get("cache-obj")
            if safe_cache and oauth_state == safe_cache.get("oauth-state"):
                user_data = data
                # 'oauth-state' is to be used only once
                safe_cache["oauth-state"] = None
                break

    # exchange 'code' for the token
    token: str | None = None
    errors: list[str] = []
    if user_data:
        code: str = request.args.get("code")
        body_data: dict[str, Any] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirec_url": _jusbr_registry.get("callback-url"),
        }
        token = __post_jusbr(user_data=user_data,
                             body_data=body_data,
                             errors=errors,
                             logger=_logger)
    else:
        msg: str = "Unknown OAuth2 code received"
        if __get_login_timeout():
            msg += " - possible operation timeout"
        errors.append(msg)

    result: Response
    if errors:
        result = jsonify({"errors": "; ".join(errors)})
        result.status_code = 400
    else:
        result = jsonify({"access_token": token})

    return result


# @flask_app.route(rule=<token_endpoint>,  # JUSBR_TOKEN_ENDPOINT: /iam/jusbr:get-token
#                  methods=["GET"])
def service_token() -> Response:
    """
    Entry point for retrieving the JusBR token.

    :return: the response containing the token, or *NOT AUTHORIZED*
    """
    # retrieve user id
    input_params: dict[str, Any] = request.args
    user_id: str = input_params.get("user-id") or input_params.get("login")

    # retrieve the token
    token: str = jusbr_get_token(user_id=user_id,
                                 logger=_logger)
    result: Response
    if token:
        result = jsonify({"token": token})
    else:
        result = Response(status=401)

    return result


def jusbr_get_token(user_id: str,
                    errors: list[str] = None,
                    logger: Logger = None) -> str:
    """
    Retrieve the authentication token for user *user_id*.

    :param user_id: the user's identification
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the token for *user_id*, or *None* if error
    """
    global _jusbr_registry

    # initialize the return variable
    result: str | None = None

    user_data: dict[str, Any] = __get_user_data(user_id=user_id,
                                                logger=logger)
    safe_cache: Cache = user_data.get("cache-obj")
    if safe_cache:
        access_expiration: int = user_data.get("access-expiration")
        now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
        if now < access_expiration:
            result = safe_cache.get("access-token")
        else:
            # access token has expired
            safe_cache["access-token"] = None
            refresh_token: str = safe_cache.get("refresh-token")
            if refresh_token:
                body_data: dict[str, str] = {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token
                }
                result = __post_jusbr(user_data=user_data,
                                      body_data=body_data,
                                      errors=errors,
                                      logger=logger)

    elif logger or isinstance(errors, list):
        err_msg: str = f"User '{user_id}' not authenticated with JusBR"
        if isinstance(errors, list):
            errors.append(err_msg)
        if logger:
            logger.error(msg=err_msg)

    return result


def jusbr_set_scope(user_id: str,
                    scope: str,
                    logger: Logger | None) -> None:
    """
    Set the OAuth2 scope of *user_id* to *scope*.

    :param user_id: the user's identification
    :param scope: the OAuth2 scope to set to the user
    :param logger: optional logger
    """
    global _jusbr_registry

    # retrieve user data
    user_data: dict[str, Any] = __get_user_data(user_id=user_id,
                                                logger=logger)
    # set the OAuth2 scope
    user_data["oauth-scope"] = scope
    if logger:
        logger.debug(f"Scope for user '{user_id}' set to '{scope}'")


def __get_login_timeout() -> int | None:
    """
    Retrieve the timeout currently applicable for the login operation.

    :return: the current login timeout, or *None* if none has been set.
    """
    global _jusbr_registry

    timeout: int = _jusbr_registry.get("client-timeout")
    return timeout if isinstance(timeout, int) and timeout > 0 else None


def __get_user_data(user_id: str,
                    logger: Logger | None) -> dict[str, Any]:
    """
    Retrieve the data for *user_id* from the registry.

    If an entry is not found for *user_id* in the registry, it is created.
    It will remain there until the user is logged out.

    :param user_id:
    :return: the data for *user_id* in the registry
    """
    global _jusbr_registry

    result: dict[str, Any] = _jusbr_registry["users"].get(user_id)
    if not result:
        result = {"access-expiration": int(datetime.now(tz=TZ_LOCAL).timestamp())}
        _jusbr_registry["users"][user_id] = result
        if logger:
            logger.debug(f"Entry for user '{user_id}' added to registry")

    return result


def __post_jusbr(user_data: dict[str, Any],
                 body_data: dict[str, Any],
                 errors: list[str] | None,
                 logger: Logger | None) -> str | None:
    """
    Send a POST request to JusBR to obtain the authentication token data, and return the access token.

    For code for token exchange, *body_data* will have the attributes
        - "grant_type": "authorization_code"
        - "code": <16-character-random-code>
        - "redirect_url": <callback-url>
    For token refresh, *body_data* will have the attributes
        - "grant_type": "refresh_token"
        - "refresh_token": <current-refresh-token>

    If the operation is successful, the token data is stored in the registry.
    Otherwise, *errors* will contain the appropriate error message.

    :param user_data: the user's data in the registry
    :param body_data: the data to send in the body of the request
    :param errors: incidental errors
    :param logger: optional logger
    :return: the access token obtained, or *None* if error
    """
    global _jusbr_registry

    # initialize the return variable
    result: str | None = None

    # complete the data to send in body of request
    body_data["client_id"] = _jusbr_registry.get("client-id")
    client_secret: str = _jusbr_registry.get("client-secret")
    if client_secret:
        body_data["client_secret"] = client_secret

    err_msg: str | None = None
    safe_cache: Cache = user_data.get("cache-obj")
    url: str = _jusbr_registry.get("auth-url")
    now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
    try:
        # JusBR return on a token request:
        # {
        #   "token_type": "Bearer",
        #   "access_token": <str>,
        #   "expires_in": <number-of-seconds>,
        #   "refresh_token": <str>,
        # }
        response: requests.Response = requests.post(url=url,
                                                    data=body_data)
        if response.status_code == 200:
            # request succeeded
            reply: dict[str, Any] = response.json()
            result = reply.get("access_token")
            safe_cache: Cache = FIFOCache(maxsize=1024)
            safe_cache["access-token"] = result
            # on token refresh, keep current refresh token if a new one is not provided
            safe_cache["refresh-token"] = reply.get("refresh_token") or body_data.get("refresh_token")
            user_data["cache-obj"] = safe_cache
            user_data["access-expiration"] = now + reply.get("expires_in")
            if logger:
                logger.debug(msg=f"POST '{url}': status {response.status_code}")
        else:
            # request resulted in error
            err_msg = (f"POST '{url}': failed, "
                       f"status {response.status_code}, reason '{response.reason}'")
            if response.status_code == 401 and "refresh_token" in body_data:
                # refresh token is no longer valid
                safe_cache["refresh-token"] = None
    except Exception as e:
        # the operation raised an exception
        err_msg = exc_format(exc=e,
                             exc_info=sys.exc_info())
        err_msg = f"POST '{url}': error '{err_msg}'"

    if err_msg:
        if isinstance(errors, list):
            errors.append(err_msg)
        if logger:
            logger.error(msg=err_msg)

    return result
