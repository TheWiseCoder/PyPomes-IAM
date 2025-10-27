# import requests
# import secrets
# import string
# import sys
# from cachetools import Cache, FIFOCache, TTLCache
# from datetime import datetime
from flask import Flask, Response, redirect, request, jsonify
from logging import Logger
from pypomes_core import (
    APP_PREFIX, TZ_LOCAL, env_get_int, env_get_str, exc_format
)
from typing import Any, Final

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

KEYCLOAK_REALM: Final[str] = env_get_str(key=f"{APP_PREFIX}_KEYCLOAK_REALM")
KEYCLOAK_URL_AUTH_BASE: Final[str] = env_get_str(key=f"{APP_PREFIX}_KEYCLOAK_URL_AUTH_BASE")
KEYCLOAK_URL_AUTH_CALLBACK: Final[str] = env_get_str(key=f"{APP_PREFIX}_KEYCLOAK_URL_AUTH_CALLBACK")

# registry structure:
# {
#    "client-id": <str>,
#    "client-secret": <str>,
#    "client-timeout": <int>,
#    "realm": <str>,
#    "auth-url": <str>,
#    "callback-url": <str>,
#    "users": {
#       "<user-id>": {
#         "cache-obj": <Cache>,
#         "oauth-scope": <str>,
#         "access-expiration": <timestamp>,
#         data in <Cache>:
#           "oauth-state": <str>
#           "access-token": <str>
#           "refresh-token": <str>
#       }
#    }
# }
_keycloak_registry: dict[str, Any] = {
    "client-id": None,
    "client-secret": None,
    "client-timeout": None,
    "realm": None,
    "auth-url": None,
    "callback-url": None,
    "users": {}
}

# dafault logger
_logger: Logger | None = None


def keycloak_setup(flask_app: Flask,
                   client_id: str = KEYCLOAK_CLIENT_ID,
                   client_secret: str = KEYCLOAK_CLIENT_SECRET,
                   client_timeout: int = KEYCLOAK_CLIENT_TIMEOUT,
                   realm: str = KEYCLOAK_REALM,
                   callback_endpoint: str = KEYCLOAK_ENDPOINT_CALLBACK,
                   token_endpoint: str = KEYCLOAK_ENDPOINT_TOKEN,
                   login_endpoint: str = KEYCLOAK_ENDPOINT_LOGIN,
                   logout_endpoint: str = KEYCLOAK_ENDPOINT_LOGOUT,
                   auth_url: str = KEYCLOAK_URL_AUTH_BASE,
                   callback_url: str = KEYCLOAK_URL_AUTH_CALLBACK,
                   logger: Logger = None) -> None:
    """
    Configure the Keycloak IAM.

    This should be invoked only once, before the first access to a Keycloak service.

    :param flask_app: the Flask application
    :param client_id: the client's identification with JusBR
    :param client_secret: the client's password with JusBR
    :param client_timeout: timeout for login authentication (in seconds,defaults to no timeout)
    :param realm: the Keycloak reals
    :param callback_endpoint: endpoint for the callback from JusBR
    :param token_endpoint: endpoint for retrieving the JusBR authentication token
    :param login_endpoint: endpoint for redirecting user to JusBR login page
    :param logout_endpoint: endpoint for terminating user access to JusBR
    :param auth_url: base URL to request the JusBR services
    :param callback_url: URL for Keycloak to callback on login
    :param logger: optional logger
    """
    global _keycloak_registry

    # establish the logger
    global _logger
    _logger = logger

    # configure the JusBR registry
    _keycloak_registry.update({
        "client-id": client_id,
        "client-secret": client_secret,
        "client-timeout": client_timeout,
        "realm": realm,
        "auth-url": auth_url,
        "callback-url": callback_url,
        "users": []
    })

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


# @flask_app.route(rule=<login_endpoint>,  # KEYCLOAK_LOGIN_ENDPOINT: /iam/keycloak:login
#                  methods=["GET"])
def service_login() -> Response:
    """
    Entry point for the Keycloak login service.

    Redirect the request to the Keycloak authentication page, with the appropriate parameters.

    :return: the response from the redirect operation
    """
    global _keycloak_registry

    # retrieve user id
    input_params: dict[str, Any] = request.args
    _user_id: str = input_params.get("user-id") or input_params.get("login")
    return Response()


# @flask_app.route(rule=<login_endpoint>,  # KEYCLOAK_LOGIN_ENDPOINT: /iam/keycloak:logout
#                  methods=["GET"])
def service_logout() -> Response:
    """
    Entry point for the JusBR logout service.

    Remove all data associating the user with JusBR from the registry.

    :return: response *OK*
    """
    global _keycloak_registry

    # retrieve user id
    input_params: dict[str, Any] = request.args
    _user_id: str = input_params.get("user-id") or input_params.get("login")
    return Response()


# @flask_app.route(rule=<callback_endpoint>,  # KEYCLOAK_CALLBACK_ENDPOINT: /iam/keycloak:callback
#                  methods=["POST"])
def service_callback() -> Response:
    """
    Entry point for the callback from Keycloak on authentication operation.

    :return: the response containing the token, or *NOT AUTHORIZED*
    """
    global _keycloak_registry
    return Response()


# @flask_app.route(rule=<token_endpoint>,  # JUSBR_TOKEN_ENDPOINT: /iam/jusbr:get-token
#                  methods=["GET"])
def service_token() -> Response:
    """
    Entry point for retrieving the Keycloak token.

    :return: the response containing the token, or *UNAUTHORIZED*
    """
    # retrieve user id
    input_params: dict[str, Any] = request.args
    _user_id: str = input_params.get("user-id") or input_params.get("login")
    return Response()


def keycloak_get_token(user_id: str,
                       errors: list[str] = None,
                       logger: Logger = None) -> str:
    """
    Retrieve the authentication token for user *user_id*.

    :param user_id: the user's identification
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the token for *user_id*, or *None* if error
    """
    global _keycloak_registry

    # initialize the return variable
    result: str | None = None
    return result

