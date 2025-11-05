from flask import Flask
from logging import Logger
from pypomes_core import (
    APP_PREFIX,
    env_get_int, env_get_str, func_get_defaulted_params
)
from typing import Any

from .iam_common import (
    _IAM_SERVERS, IamServer, IamParam, _iam_lock
)
from .iam_actions import action_token
from .iam_services import (
    service_login, service_logout, service_callback, service_exchange, service_token
)


def iam_setup_server(iam_server: IamServer,
                     base_url: str = None,
                     admin_id: str = None,
                     admin_secret: str = None,
                     client_id: str = None,
                     client_realm: str = None,
                     client_secret: str = None,
                     login_timeout: int = None,
                     public_key_lifetime: int = None,
                     recipient_attribute: str = None) -> None:
    """
    Setup the *IAM* server *iam_server*.

    For the parameters not effectively passed, an attempt is made to obtain a value from the corresponding
    environment variables. Most parameters are required to have values, which must be assigned either
    throught the function invocation, or from the corresponding environment variables.

    The parameters *admin_id* and *admin_* are required only if administrative are task are planned.
    The optional parameter *client_timeout* refers to the maximum time in seconds allowed for the
    user to login at the *IAM* server's login page, and defaults to no time limit.

    The parameter *client_secret* is required in most requests to the *IAM* server. In the case
    it is not provided, but *admin_id* and *admin_secret* are, it is obtained from the *IAM* server itself
    the first time it is needed.

    :param iam_server: identifies the supported *IAM* server (currently, *jusbr* or *keycloak*)
    :param base_url: base URL to request services
    :param admin_id: identifies the realm administrator
    :param admin_secret: password for the realm administrator
    :param client_id: the client's identification with the *IAM* server
    :param client_realm: the client realm
    :param client_secret: the client's password with the *IAM* server
    :param login_timeout: timeout for login authentication (in seconds,defaults to no timeout)
    :param public_key_lifetime: how long to use *IAM* server's public key, before refreshing it (in seconds)
    :param recipient_attribute: attribute in the token's payload holding the token's subject
    """
    # obtain the defaulted parameters
    defaulted_params: list[str] = func_get_defaulted_params()

    # read from the environment variables
    prefix: str = iam_server.name
    if "base_url" in defaulted_params:
        base_url = env_get_str(key=f"{APP_PREFIX}_{prefix}_URL_AUTH_BASE")
    if "admin_id" in defaulted_params:
        admin_id = env_get_str(key=f"{APP_PREFIX}_{prefix}_ADMIN_ID")
    if "admin_secret" in defaulted_params:
        admin_secret = env_get_str(key=f"{APP_PREFIX}_{prefix}_ADMIN_SECRET")
    if "client_id" in defaulted_params:
        client_id = env_get_str(key=f"{APP_PREFIX}_{prefix}_CLIENT_ID")
    if "client_realm" in defaulted_params:
        client_realm = env_get_str(key=f"{APP_PREFIX}_{prefix}_CLIENT_REALM")
    if "client_secret" in defaulted_params:
        client_secret = env_get_str(key=f"{APP_PREFIX}_{prefix}_CLIENT_SECRET")
    if "login_timeout" in defaulted_params:
        login_timeout = env_get_str(key=f"{APP_PREFIX}_{prefix}_LOGIN_TIMEOUT")
    if "public_key_lifetime" in defaulted_params:
        public_key_lifetime = env_get_int(key=f"{APP_PREFIX}_{prefix}_PUBLIC_KEY_LIFETIME")
    if "recipient_attribute" in defaulted_params:
        recipient_attribute = env_get_str(key=f"{APP_PREFIX}_{prefix}_RECIPIENT_ATTR")

    # configure the Keycloak registry
    with _iam_lock:
        _IAM_SERVERS[iam_server] = {
            IamParam.URL_BASE: base_url,
            IamParam.CLIENT_ID: client_id,
            IamParam.CLIENT_REALM: client_realm,
            IamParam.CLIENT_SECRET: client_secret,
            IamParam.RECIPIENT_ATTR: recipient_attribute,
            IamParam.ADMIN_ID: admin_id,
            IamParam.ADMIN_SECRET: admin_secret,
            IamParam.LOGIN_TIMEOUT: login_timeout,
            IamParam.PK_LIFETIME: public_key_lifetime,
            IamParam.PK_EXPIRATION: 0,
            IamParam.PUBLIC_KEY: None,
            IamParam.USERS: {}
        }


def iam_setup_endpoints(flask_app: Flask,
                        iam_server: IamServer,
                        callback_endpoint: str = None,
                        exchange_endpoint: str = None,
                        login_endpoint: str = None,
                        logout_endpoint: str = None,
                        token_endpoint: str = None) -> None:
    """
    Setup the endpoints for accessing the services provided by *iam_server*.

    For the parameters not effectively passed, an attempt is made to obtain a value from the corresponding
    environment variables.

    :param flask_app: the Flask application
    :param iam_server: identifies the supported *IAM* server (currently, *jusbr* or *keycloak*)
    :param callback_endpoint: endpoint for the callback from the front end
    :param exchange_endpoint: endpoint for requesting token exchange
    :param login_endpoint: endpoint for redirecting user to the *IAM* server's login page
    :param logout_endpoint: endpoint for terminating user access
    :param token_endpoint: endpoint for retrieving authentication token
    """
    # obtain the defaulted parameters
    defaulted_params: list[str] = func_get_defaulted_params()

    # read from the environment variables
    prefix: str = iam_server.name
    if "callback_endpoint" in defaulted_params:
        callback_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_CALLBACK")
    if "exchange_endpoint" in defaulted_params:
        callback_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_EXCHANGE")
    if "login_endpoint" in defaulted_params:
        login_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_LOGIN")
    if "logout_endpoint" in defaulted_params:
        logout_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_LOGOUT")
    if "token_endpoint" in defaulted_params:
        token_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_TOKEN")

    # establish the endpoints
    if callback_endpoint:
        flask_app.add_url_rule(rule=callback_endpoint,
                               endpoint=f"{iam_server}-callback",
                               view_func=service_callback,
                               methods=["GET"])
    if exchange_endpoint:
        flask_app.add_url_rule(rule=exchange_endpoint,
                               endpoint=f"{iam_server}-exchange",
                               view_func=service_exchange,
                               methods=["POST"])
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
