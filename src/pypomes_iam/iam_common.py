import sys
from datetime import datetime
from enum import StrEnum
from logging import Logger
from pypomes_core import (
    APP_PREFIX, TZ_LOCAL,
    env_get_int, env_get_str, env_get_strs
)
from pypomes_crypto import jwt_get_public_key
from threading import RLock
from typing import Any, Final

_members: dict[str, str] = {key.upper(): key.lower() for key in
                            env_get_strs(key=f"{APP_PREFIX}_AUTH_SERVERS")}
IamServer: type[StrEnum] = StrEnum("IamServer", _members)
del _members


class ServerParam(StrEnum):
    """
    Parameters for configuring *IAM* servers.
    """

    ADMIN_ID = "admin-id"
    ADMIN_SECRET = "admin-secret"
    CLIENT_ID = "client-id"
    CLIENT_REALM = "client-realm"
    CLIENT_SECRET = "client-secret"
    ENDPOINT_CALLBACK = "endpoint-callback"
    ENDPOINT_CALLBACK_EXCHANGE = "endpoint-callback-exchange"
    ENDPOINT_LOGIN = "endpoint-login"
    ENDPOINT_LOGOUT = "endpoint_logout"
    ENDPOINT_REFRESH = "endpoint-refresh"
    ENDPOINT_TOKEN = "endpoint-token"
    ENDPOINT_EXCHANGE = "endpoint-exchange"
    LOGIN_TIMEOUT = "login-timeout"
    PK_EXPIRATION = "pk-expiration"
    PK_LIFETIME = "pk-lifetime"
    RECIPIENT_ATTR = "recipient-attr"
    TRUSTED_HOSTS = "trusted-hosts"
    # dynamic attributes
    PUBLIC_KEY = "public-key"
    URL_BASE = "url-base"
    USERS = "users"


class UserParam(StrEnum):
    """
    Parameters for handling *IAM* users.
    """
    ACCESS_TOKEN = "access-token"
    REFRESH_TOKEN = "refresh-token"
    ACCESS_EXPIRATION = "access-expiration"
    REFRESH_EXPIRATION = "refresh-expiration"
    # transient attributes
    LOGIN_EXPIRATION = "login-expiration"
    LOGIN_ID = "login-id"
    REDIRECT_URI = "redirect-uri"


def __get_iam_data() -> dict[IamServer, dict[ServerParam, Any]]:
    """
    Obtain the configuration data for select *IAM* servers.

    The configuration parameters for the IAM servers are specified dynamically with environment variables,
    or dynamically with calls to *iam_setup_server()*. Specifying configuration parameters with environment
    variables can be done by following these steps:

    1. Specify *<APP_PREFIX>_AUTH_SERVERS* with a list of names among the values found in *IamServer* class
       and the data set below for each server, where *<IAM>* stands for the server's name as presented in
       *IamServer* class:
          - *<APP_PREFIX>_<IAM>_ADMIN_ID*           (optional, required if administrative duties are performed)
          - *<APP_PREFIX>_<IAM>_ADMIN_PWD*          (optional, required if administrative duties are performed)
          - *<APP_PREFIX>_<IAM>_CLIENT_ID*          (required)
          - *<APP_PREFIX>_<IAM>_CLIENT_REALM*       (required)
          - *<APP_PREFIX>_<IAM>_CLIENT_SECRET*      (required)
          - *<APP_PREFIX>_<IAM>_LOGIN_TIMEOUT*      (optional, defaults to no timeout)
          - *<APP_PREFIX>_<IAM>_PK_LIFETIME*        (optional, defaults to non-terminating lifetime)
          - *<APP_PREFIX>_<IAM>_RECIPIENT_ATTR*     (required)
          - *<APP_PREFIX>_<IAM>_TRUSTED_HOSTS*      (optional)
          - *<APP_PREFIX>_<IAM>_URL_BASE*           (required)

    2. A group of special environment variables identifying endpoints for authentication services may be specified,
       following the same scheme as presented in item *1* above. These are the second part of the *IAM* server's
       setup, and are meant to be used by function *iam_setup_endpoints()*, wherein the values in those variables
       would represent default values for its parameters, respectively:
          - *<APP_PREFIX>_<IAM>_ENDPOINT_CALLBACK*
          - *<APP_PREFIX>_<IAM>_ENDPOINT_CALLBACK_EXCHANGE*
          - *<APP_PREFIX>_<IAM>_ENDPOINT_EXCHANGE*
          - *<APP_PREFIX>_<IAM>_ENDPOINT_LOGIN*
          - *<APP_PREFIX>_<IAM>_ENDPOINT_LOGOUT*
          - *<APP_PREFIX>_<IAM>_ENDPOINT_REFRESH*
          - *<APP_PREFIX>_<IAM>_ENDPOINT_TOKEN*
          - *<APP_PREFIX>_<IAM>_ENDPOINT_USERINFO*

    3. One of the above endpoints, namely *<APP_PREFIX>_<IAM>_ENDPOINT_TOKEN*, requires special protection.
       By its very nature, it is expected to be seldomly needed, and if indeed used, limited in scope and
       restricted to specific parties. This is the purpose of the special environment variable
       *<APP_PREFIX>_<IAM>_TRUSTED_HOSTS*, which, if specified, will list the only requesting hosts
       allowed to be serviced at that endpoint.

    :return: the configuration data for the select *IAM* servers.
    """
    # initialize the return variable
    result: dict[IamServer, dict[ServerParam, Any]] = {}

    for server in IamServer:
        prefix = server.name
        result[server] = {
            ServerParam.ADMIN_ID: env_get_str(key=f"{APP_PREFIX}_{prefix}_ADMIN_ID"),
            ServerParam.ADMIN_SECRET: env_get_str(key=f"{APP_PREFIX}_{prefix}_ADMIN_SECRET"),
            ServerParam.CLIENT_ID: env_get_str(key=f"{APP_PREFIX}_{prefix}_CLIENT_ID"),
            ServerParam.CLIENT_REALM: env_get_str(key=f"{APP_PREFIX}_{prefix}_CLIENT_REALM"),
            ServerParam.CLIENT_SECRET: env_get_str(key=f"{APP_PREFIX}_{prefix}_CLIENT_SECRET"),
            ServerParam.LOGIN_TIMEOUT: env_get_str(key=f"{APP_PREFIX}_{prefix}_LOGIN_TIMEOUT"),
            ServerParam.PK_LIFETIME: env_get_int(key=f"{APP_PREFIX}_{prefix}_PK_LIFETIME"),
            ServerParam.RECIPIENT_ATTR: env_get_str(key=f"{APP_PREFIX}_{prefix}_RECIPIENT_ATTR"),
            ServerParam.TRUSTED_HOSTS: env_get_strs(key=f"{APP_PREFIX}_{prefix}_TRUSTED_HOSTS"),
            ServerParam.URL_BASE: env_get_str(key=f"{APP_PREFIX}_{prefix}_URL_BASE"),
            # dynamically set
            ServerParam.PK_EXPIRATION: 0,
            ServerParam.PUBLIC_KEY: None,
            ServerParam.USERS: {}
        }

    return result


# registry structure:
# { <IamServer>:
#    {
#       "base-url": <str>,
#       "admin-id": <str>,
#       "admin-secret": <str>,
#       "client-id": <str>,
#       "client-secret": <str>,
#       "client-realm": <str,
#       "client-timeout": <int>,
#       "recipient-attr": <str>,
#       # dynamic attributes
#       "public-key": <str>,
#       "pk-lifetime": <int>,
#       "pk-expiration": <int>,
#       "truted-requesters>: <list[str]>,
#       "users": {}
#    },
#    ...
# }
# data in "users":
# {
#   "<user-id>": {
#      "access-token": <str>
#      "refresh-token": <str>
#      "access-expiration": <timestamp>,
#      "refresh-expiration": <timestamp>,
#      # transient attributes
#      "login-expiration": <timestamp>,
#      "login-id": <str>,
#      "redirect-uri": <str>
#   },
#   ...
# }
_IAM_SERVERS: Final[dict[IamServer, dict[ServerParam, Any]]] = __get_iam_data()


# the lock protecting the data in '_<IAM>_SERVERS'
# (because it is 'Final' and set at declaration time, it can be accessed through simple imports)
_iam_lock: Final[RLock] = RLock()


def _iam_server_from_endpoint(endpoint: str,
                              errors: list[str] | None,
                              logger: Logger | None) -> IamServer | None:
    """
    Retrieve the registered *IAM* server associated with the service's invocation *endpoint*.

    :param endpoint: the service's invocation endpoint
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the corresponding *IAM* server, or *None* if one could not be obtained
    """
    # initialize the return variable
    result: type(IamServer) | None = None

    for iam_server in _IAM_SERVERS:
        if endpoint.startswith(iam_server):
            result = iam_server
            break

    if not result:
        msg: str = f"Unable to find a IAM server to service endpoint '{endpoint}'"
        if logger:
            logger.error(msg=msg)
        if isinstance(errors, list):
            errors.append(msg)

    return result


def _iam_server_from_issuer(issuer: str,
                            errors: list[str] | None,
                            logger: Logger | None) -> IamServer | None:
    """
    Retrieve the registered *IAM* server associated with the token's *issuer*.

    :param issuer: the token's issuer
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the corresponding *IAM* server, or *None* if one could not be obtained
    """
    # initialize the return variable
    result: type(IamServer) | None = None

    for iam_server, registry in _IAM_SERVERS.items():
        base_url: str = f"{registry[ServerParam.URL_BASE]}/realms/{registry[ServerParam.CLIENT_REALM]}"
        if base_url == issuer:
            result = IamServer(iam_server)
            break

    if not result:
        msg: str = f"Unable to find a IAM server associated with token issuer '{issuer}'"
        if logger:
            logger.error(msg=msg)
        if isinstance(errors, list):
            errors.append(msg)

    return result


def _get_public_key(iam_server: IamServer,
                    errors: list[str] | None,
                    logger: Logger | None) -> str:
    """
    Obtain the public key used by *iam_server* to sign the authentication tokens.

    The signaature is obtained and stored in *PEM* (Privacy-Enhanced Mail) format.

    :param iam_server: the reference registered *IAM* server
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the public key in *PEM* format, or *None* if error
    """
    # initialize the return variable
    result: str | None = None

    registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                 errors=errors,
                                                 logger=logger)
    if registry:
        now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
        if now > registry[ServerParam.PK_EXPIRATION]:
            # obtain the public key from the token issuer
            issuer: str = f"{registry[ServerParam.URL_BASE]}/realms/{registry[ServerParam.CLIENT_REALM]}"
            registry[ServerParam.PUBLIC_KEY] = jwt_get_public_key(issuer=issuer,
                                                                  fmt="PEM",
                                                                  errors=errors,
                                                                  logger=logger)
            lifetime: int = registry[ServerParam.PK_LIFETIME] or 0
            registry[ServerParam.PK_EXPIRATION] = now + lifetime if lifetime else sys.maxsize

    if not errors:
        result = registry[ServerParam.PUBLIC_KEY]

    return result


def _get_login_timeout(iam_server: IamServer,
                       errors: list[str] | None,
                       logger: Logger) -> int | None:
    """
    Retrieve the timeout currently applicable for the login operation.

    :param iam_server: the reference registered *IAM* server
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the current login timeout, or *None* if the server is unknown or none has been set.
    """
    # initialize the return variable
    result: int | None = None

    registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                 errors=errors,
                                                 logger=logger)
    if registry:
        timeout: int = registry.get("client-timeout")
        if isinstance(timeout, int) and timeout > 0:
            result = timeout

    return result


def _get_user_data(iam_server: IamServer,
                   user_id: str,
                   errors: list[str] | None,
                   logger: Logger | None) -> dict[str, Any] | None:
    """
    Retrieve the data for *user_id* from *iam_server*'s registry.

    If an entry is not found for *user_id* in the registry, it is created.
    It will remain there until the user is logged out.

    :param iam_server: the reference registered *IAM* server
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the data for *user_id* in *iam_server*'s registry, or *None* if the server is unknown
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    users: dict[str, dict[str, Any]] = _get_iam_users(iam_server=iam_server,
                                                      errors=errors,
                                                      logger=logger)
    if isinstance(users, dict):
        result = users.get(user_id)
        if not result:
            result = {
                UserParam.ACCESS_TOKEN: None,
                UserParam.REFRESH_TOKEN: None,
                UserParam.ACCESS_EXPIRATION: int(datetime.now(tz=TZ_LOCAL).timestamp()),
                UserParam.REFRESH_EXPIRATION: sys.maxsize
            }
            users[user_id] = result
            if logger:
                logger.debug(msg=f"Entry for '{user_id}' added to {iam_server}'s registry")
        elif logger:
            logger.debug(msg=f"Entry for '{user_id}' obtained from {iam_server}'s registry")

    return result


def _get_iam_registry(iam_server: IamServer,
                      errors: list[str] | None,
                      logger: Logger | None) -> dict[str, Any]:
    """
    Retrieve the registry associated with *iam_server*.

    :param iam_server: the reference registered *IAM* server
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the registry associated with *iam_server*, or *None* if the server is unknown
    """
    # assign the return variable
    result: dict[str, Any] = _IAM_SERVERS.get(iam_server)

    if not result:
        msg = f"Unknown IAM server '{iam_server}'"
        if logger:
            logger.error(msg=msg)
        if isinstance(errors, list):
            errors.append(msg)

    return result


def _get_iam_property(iam_server: IamServer,
                      attr: ServerParam,
                      errors: list[str] | None,
                      logger: Logger | None) -> list[str] | str | int:
    """
    Retrieve the value of *attr* in the registry associated with *iam_server*.

    :param iam_server: the reference registered *IAM* server
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the registry associated with *iam_server*, or *None* if the server is unknown
    """
    # obtain the registry
    registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                 errors=errors,
                                                 logger=logger)
    return registry[attr] if registry else None


def _get_iam_users(iam_server: IamServer,
                   errors: list[str] | None,
                   logger: Logger | None) -> dict[str, dict[str, Any]]:
    """
    Retrieve the users data storage in *iam_server*'s registry.

    :param iam_server: the reference registered *IAM* server
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the users data storage in *iam_server*'s registry, or *None* if the server is unknown
    """
    registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                 errors=errors,
                                                 logger=logger)
    return registry[ServerParam.USERS] if registry else None
