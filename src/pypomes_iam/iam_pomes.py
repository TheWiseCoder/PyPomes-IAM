from flask import Flask
from pypomes_core import (
    APP_PREFIX,
    env_get_int, env_get_str, env_get_strs,
    func_capture_params, func_defaulted_params
)

from .iam_common import (
    _IAM_SERVERS, IamServer, ServerParam, _iam_lock
)
from .iam_services import (
    service_login, service_logout,
    service_callback, service_callback_exchange,
    service_exchange, service_refresh, service_userinfo
)


@func_capture_params
def iam_setup_server(iam_server: IamServer,
                     admin_id: str = None,
                     admin_secret: str = None,
                     client_id: str = None,
                     client_realm: str = None,
                     client_secret: str = None,
                     login_timeout: int = None,
                     pk_lifetime: int = None,
                     recipient_attr: str = None,
                     trusted_hosts: list[str] = None,
                     url_base: str = None) -> None:
    """
    Setup the *IAM* server *iam_server*.

    For the parameters not effectively passed, an attempt is made to obtain a value from the corresponding
    environment variables. Most parameters are required to have values, which must be assigned either
    throught the function invocation, or from the corresponding environment variables.

    The parameters *admin_id* and *admin_* are required only if performing administrative task are intended.
    The optional parameter *client_timeout* refers to the maximum time in seconds allowed for the
    user to login at the *IAM* server's login page, and defaults to no time limit.

    The parameter *client_secret* is required in most requests to the *IAM* server. In the case
    it is not provided, but *admin_id* and *admin_secret* are, it is obtained from the *IAM* server itself
    the first time it is needed.

    :param iam_server: identifies the supported *IAM* server
    :param admin_id: identifies the realm administrator
    :param admin_secret: password for the realm administrator
    :param client_id: the client's identification with the *IAM* server
    :param client_realm: the client's realm
    :param client_secret: the client's password with the *IAM* server
    :param login_timeout: timeout for login authentication (in seconds,defaults to no timeout)
    :param pk_lifetime: how long to use *IAM* server's public key, before refreshing it (in seconds)
    :param recipient_attr: attribute in the token's payload holding the token's subject
    :param trusted_hosts: one or more hosts allowed to be serviced at the 'get token' endpoint
    :param url_base: base URL to request services
    """
    # obtain the defaulted parameters
    defaulted_params: list[str] = func_defaulted_params.get()

    # read from the environment variables
    prefix: str = iam_server.name
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
    if "pk_lifetime" in defaulted_params:
        pk_lifetime = env_get_int(key=f"{APP_PREFIX}_{prefix}_PK_LIFETIME")
    if "recipient_attr" in defaulted_params:
        recipient_attr = env_get_str(key=f"{APP_PREFIX}_{prefix}_RECIPIENT_ATTR")
    if "trusted_hosts" in defaulted_params:
        trusted_hosts = env_get_strs(key=f"{APP_PREFIX}_{prefix}_TRUSTED_HOSTS")
    if "url_base" in defaulted_params:
        url_base = env_get_str(key=f"{APP_PREFIX}_{prefix}_URL_BASE")

    # configure the IAM server's registry
    with _iam_lock:
        _IAM_SERVERS[iam_server] = {
            ServerParam.CLIENT_ID: client_id,
            ServerParam.CLIENT_REALM: client_realm,
            ServerParam.CLIENT_SECRET: client_secret,
            ServerParam.RECIPIENT_ATTR: recipient_attr,
            ServerParam.ADMIN_ID: admin_id,
            ServerParam.ADMIN_SECRET: admin_secret,
            ServerParam.LOGIN_TIMEOUT: login_timeout,
            ServerParam.PK_LIFETIME: pk_lifetime,
            ServerParam.TRUSTED_HOSTS: trusted_hosts,
            ServerParam.URL_BASE: url_base,
            # dynamic attributes
            ServerParam.PK_EXPIRATION: 0,
            ServerParam.PUBLIC_KEY: None,
            ServerParam.USERS: {}
        }


@func_capture_params
def iam_setup_endpoints(flask_app: Flask,
                        iam_server: IamServer,
                        callback_endpoint: str = None,
                        callback_exchange_endpoint: str = None,
                        exchange_endpoint: str = None,
                        login_endpoint: str = None,
                        logout_endpoint: str = None,
                        refresh_endpoint: str = None,
                        token_endpoint: str = None,
                        userinfo_endpoint: str = None) -> None:
    """
    Setup the endpoints for accessing the services provided by *iam_server*.

    For the parameters not effectively passed, an attempt is made to obtain a value from the corresponding
    environment variables.

    :param flask_app: the Flask application
    :param iam_server: identifies the supported *IAM* server
    :param callback_endpoint: endpoint for the callback from the front end
    :param callback_exchange_endpoint: endpoint for the combination callback and exchange
    :param exchange_endpoint: endpoint for requesting token exchange
    :param login_endpoint: endpoint for redirecting user to the *IAM* server's login page
    :param logout_endpoint: endpoint for terminating user access
    :param refresh_endpoint: endpoint for refreshing an authentication token
    :param token_endpoint: endpoint for acquiring an authentication token
    :param userinfo_endpoint: endpoint for retrieving user data
    """
    # obtain the defaulted parameters
    defaulted_params: list[str] = func_defaulted_params.get()

    # read from the environment variables
    prefix: str = iam_server.name
    if "callback_endpoint" in defaulted_params:
        callback_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_CALLBACK")
    if "callback_exchange_endpoint" in defaulted_params:
        callback_exchange_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_CALLBACK_EXCHANGE")
    if "exchange_endpoint" in defaulted_params:
        exchange_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_EXCHANGE")
    if "login_endpoint" in defaulted_params:
        login_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_LOGIN")
    if "logout_endpoint" in defaulted_params:
        logout_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_LOGOUT")
    if "refresh_endpoint" in defaulted_params:
        refresh_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_REFRESH")
    if "token_endpoint" in defaulted_params:
        token_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_TOKEN")
    if "userinfo_endpoint" in defaulted_params:
        userinfo_endpoint = env_get_str(key=f"{APP_PREFIX}_{prefix}_ENDPOINT_USERINFO")

    # establish the endpoints
    if callback_endpoint:
        flask_app.add_url_rule(rule=callback_endpoint,
                               endpoint=f"{iam_server}-callback",
                               view_func=service_callback,
                               methods=["GET"])
    if callback_exchange_endpoint:
        flask_app.add_url_rule(rule=callback_exchange_endpoint,
                               endpoint=f"{iam_server}-callback-exchange",
                               view_func=service_callback_exchange,
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
                               methods=["POST"])
    if refresh_endpoint:
        flask_app.add_url_rule(rule=refresh_endpoint,
                               endpoint=f"{iam_server}-refresh",
                               view_func=service_refresh,
                               methods=["GET"])
    if token_endpoint:
        flask_app.add_url_rule(rule=token_endpoint,
                               endpoint=f"{iam_server}-token",
                               view_func=service_refresh,
                               methods=["GET"])
    if userinfo_endpoint:
        flask_app.add_url_rule(rule=userinfo_endpoint,
                               endpoint=f"{iam_server}-userinfo",
                               view_func=service_userinfo,
                               methods=["GET"])
