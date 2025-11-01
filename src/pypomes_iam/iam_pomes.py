from flask import Flask
from logging import Logger
from typing import Any

from .iam_common import (
    _IAM_SERVERS, IamServer, IamParam, _iam_lock
)
from .iam_actions import action_token
from .iam_services import (
    service_login, service_logout, service_callback, service_exchange, service_token
)


def iam_setup(flask_app: Flask,
              iam_server: IamServer,
              base_url: str,
              client_id: str,
              client_secret: str,
              client_realm: str,
              recipient_attribute: str,
              client_timeout: int = None,
              admin_id: str = None,
              admin_secret: str = None,
              public_key_lifetime: int = None,
              callback_endpoint: str = None,
              login_endpoint: str = None,
              logout_endpoint: str = None,
              token_endpoint: str = None,
              exchange_endpoint: str = None) -> None:
    """
    Establish the provided parameters for configuring the *IAM* server *iam_server*.

    The parameters *admin_id* and *admin_*

    :param flask_app: the Flask application
    :param iam_server: identifies the supported *IAM* server (*jusbr* or *keycloak*)
    :param base_url: base URL to request services
    :param client_realm: the client realm
    :param client_id: the client's identification with the *IAM* server
    :param client_secret: the client's password with the *IAM* server
    :param client_timeout: timeout for login authentication (in seconds,defaults to no timeout)
    :param admin_id: identifies the realm administrator
    :param admin_secret: password for the realm administrator
    :param public_key_lifetime: how long to use *IAM* server's public key, before refreshing it (in seconds)
    :param recipient_attribute: attribute in the token's payload holding the token's subject
    :param callback_endpoint: endpoint for the callback from the front end
    :param login_endpoint: endpoint for redirecting user to the *IAM* server's login page
    :param logout_endpoint: endpoint for terminating user access
    :param token_endpoint: endpoint for retrieving authentication token
    :param exchange_endpoint: endpoint for requesting token exchange
    """

    # configure the Keycloak registry
    with _iam_lock:
        _IAM_SERVERS[iam_server] = {
            IamParam.URL_BASE: base_url,
            IamParam.CLIENT_ID: client_id,
            IamParam.CLIENT_REALM: client_realm,
            IamParam.CLIENT_SECRET: client_secret,
            IamParam.CLIENT_TIMEOUT: client_timeout,
            IamParam.RECIPIENT_ATTR: recipient_attribute,
            IamParam.PK_EXPIRATION: 0,
            IamParam.PUBLIC_KEY: None,
            IamParam.USERS: {}
        }
        if admin_id and admin_secret:
            IamParam.ADMIN_ID = admin_id
            IamParam.ADMIN_SECRET = admin_secret

        if public_key_lifetime:
            IamParam.PK_LIFETIME = public_key_lifetime

    # establish the endpoints
    if callback_endpoint:
        flask_app.add_url_rule(rule=callback_endpoint,
                               endpoint=f"{iam_server}-callback",
                               view_func=service_callback,
                               methods=["GET"])
    if login_endpoint:
        flask_app.add_url_rule(rule=login_endpoint,
                               endpoint=f"{iam_server}-login",
                               view_func=service_login,
                               methods=["GET"])
    if logout_endpoint:
        flask_app.add_url_rule(rule=logout_endpoint,
                               endpoint=f"{iam_server}-logout",
                               view_func=service_logout,
                               methods=["GET"])
    if token_endpoint:
        flask_app.add_url_rule(rule=token_endpoint,
                               endpoint=f"{iam_server}-token",
                               view_func=service_token,
                               methods=["GET"])
    if exchange_endpoint:
        flask_app.add_url_rule(rule=exchange_endpoint,
                               endpoint=f"{iam_server}-exchange",
                               view_func=service_exchange,
                               methods=["POST"])


def iam_get_token(iam_server: IamServer,
                  user_id: str,
                  errors: list[str] = None,
                  logger: Logger = None) -> str:
    """
    Retrieve an authentication token for *user_id*.

    :param iam_server: identifies the *IAM* server
    :param user_id: identifies the user
    :param errors: incidental errors
    :param logger: optional logger
    :return: the uthentication tokem
    """
    # declare the return variable
    result: str

    # retrieve the token
    args: dict[str, Any] = {"user-id": user_id}
    with _iam_lock:
        result = action_token(iam_server=iam_server,
                              args=args,
                              errors=errors,
                              logger=logger)
    return result
