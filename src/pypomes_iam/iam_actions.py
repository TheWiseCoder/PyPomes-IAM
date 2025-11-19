import json
import requests
import secrets
import string
import sys
from datetime import datetime
from logging import Logger
from pypomes_core import TZ_LOCAL, exc_format
from pypomes_crypto import jwt_get_claim, jwt_validate
from typing import Any

from .iam_common import (
    IamServer, ServerParam, UserParam, _iam_lock, _get_iam_users,
    _get_iam_registry, _get_iam_property, _get_public_key,
    _get_login_timeout, _get_user_data, _iam_server_from_issuer
)


def iam_login(iam_server: IamServer,
              args: dict[str, Any],
              errors: list[str] = None,
              logger: Logger = None) -> str:
    """
    Build the URL for redirecting the request to *iam_server*'s authentication page.

    The expected attributes in *args* are:
        - user-id: optional, identifies the reference user (alias: 'login')
        - redirect-uri: a parameter to be added to the query part of the returned URL
        -target-idp: optionally, identify a target identity provider for the login operation

    If provided, the user identification will be validated against the authorization data
    returned by *iam_server* upon login. On success, the appropriate URL for invoking
    the IAM server's authentication page is returned.

    if 'target_idp' is provided as an attribute in *args*, the OAuth2 state variable included in the
    returned URL will be postfixed with the string *#idp=<target-idp>*. At the callback endpoint,
    this instructs *iam_server* to act as a broker, forwading the authentication process to the
    *IAM* server *target-idp*.

    :param iam_server: the reference registered *IAM* server
    :param args: the arguments passed when requesting the service
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the callback URL, with the appropriate parameters, of *None* if error
    """
    # initialize the return variable
    result: str | None = None

    # obtain the optional user's identification
    user_id: str = args.get("user-id") or args.get("login")

    # obtain the optional target identity provider
    target_idp: str = args.get("target-idp")

    # build the user data
    # ('oauth_state' is a randomly-generated string, thus 'user_data' is always a new entry)
    oauth_state: str = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    if target_idp:
        oauth_state += f"_{target_idp}"

    with _iam_lock:
        # retrieve the user data from the IAM server's registry
        user_data: dict[str, Any] = _get_user_data(iam_server=iam_server,
                                                   user_id=oauth_state,
                                                   errors=errors,
                                                   logger=logger)
        if user_data:
            user_data[UserParam.LOGIN_ID] = user_id
            timeout: int = _get_login_timeout(iam_server=iam_server,
                                              errors=errors,
                                              logger=logger)
            if not errors:
                user_data[UserParam.LOGIN_EXPIRATION] = (int(datetime.now(tz=TZ_LOCAL).timestamp()) + timeout) \
                    if timeout else None
                redirect_uri: str = args.get(UserParam.REDIRECT_URI)
                user_data[UserParam.REDIRECT_URI] = redirect_uri

                # build the login url
                registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                             errors=errors,
                                                             logger=logger)
                if registry:
                    base_url: str = f"{registry[ServerParam.URL_BASE]}/realms/{registry[ServerParam.CLIENT_REALM]}"
                    result = (f"{base_url}/protocol/openid-connect/auth"
                              f"?response_type=code&scope=openid"
                              f"&client_id={registry[ServerParam.CLIENT_ID]}"
                              f"&redirect_uri={redirect_uri}"
                              f"&state={oauth_state}")
                    if target_idp:
                        # HAZARD: the name 'kc_idp_hint' is Keycloak-specific
                        result += f"&kc_idp_hint={target_idp}"

    return result


def iam_logout(iam_server: IamServer,
               args: dict[str, Any],
               errors: list[str] = None,
               logger: Logger = None) -> None:
    """
    Logout the user, by removing all data associating it from *iam_server*'s registry.

    The user is identified by the attribute *user-id* or *login*, provided in *args*.

    A logout request is sent to *iam_server* and, if successful, remove all data relating to the user
    from the *IAM* server's registry.

    :param iam_server: the reference registered *IAM* server
    :param args: the arguments passed when requesting the service
    :param errors: incidental error messages
    :param logger: optional logger
    """
    # obtain the user's identification
    user_id: str = args.get("user-id") or args.get("login")

    if user_id:
        with _iam_lock:
            # retrieve the IAM server's registry and the data for all users therein
            registry: dict[str, Any] = _get_iam_registry(iam_server,
                                                         errors=errors,
                                                         logger=logger)
            users: dict[str, dict[str, Any]] = registry[ServerParam.USERS] if registry else {}
            user_data: dict[str, Any] = users.get(user_id)
            if user_data:
                # request the IAM server to logout 'client_id'
                client_secret: str = __get_client_secret(iam_server=iam_server,
                                                         errors=errors,
                                                         logger=logger)
                if client_secret:
                    url: str = (f"{registry[ServerParam.URL_BASE]}/realms/{registry[ServerParam.CLIENT_REALM]}"
                                "/protocol/openid-connect/logout")
                    header_data: dict[str, str] = {
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
                    body_data: dict[str, Any] = {
                        "client_id": registry[ServerParam.CLIENT_ID],
                        "client_secret": client_secret,
                        "refresh_token": user_data[UserParam.REFRESH_TOKEN]
                    }
                    #  log the POST
                    if logger:
                        logger.debug(msg=f"POST {url}")
                    try:
                        response: requests.Response = requests.post(url=url,
                                                                    headers=header_data,
                                                                    data=body_data)
                        if response.status_code in [200, 204]:
                            # request succeeded
                            if logger:
                                logger.debug(msg="POST success")
                        else:
                            # request failed, report the problem
                            msg: str = f"POST failure, status {response.status_code}, reason {response.reason}"
                            if logger:
                                logger.error(msg=msg)
                            if isinstance(errors, list):
                                errors.append(msg)
                    except Exception as e:
                        # the operation raised an exception
                        msg: str = exc_format(exc=e,
                                              exc_info=sys.exc_info())
                        if logger:
                            logger.error(msg=msg)
                        if isinstance(errors, list):
                            errors.append(msg)

                    if not errors and user_id in users:
                        users.pop(user_id)
                        if logger:
                            logger.debug(msg=f"User '{user_id}' removed from {iam_server}'s registry")
    else:
        msg: str = "User identification not provided"
        if logger:
            logger.error(msg=msg)
        if isinstance(errors, list):
            errors.append(msg)


def iam_refresh(iam_server: IamServer,
                args: dict[str, Any],
                errors: list[str] = None,
                logger: Logger = None) -> dict[str, str]:
    """
    Refresh the authentication token for the user, from *iam_server*.

    The expected parameters in *args* are:
        - user-id: identification for the reference user (alias: 'login')
        - access-token: the old, probable expíred, token to be refreshed

    On success, the returned *dict* will contain the following JSON:
        {
            "access-token": <token>,
            "user-id": <user-identification
        }

    :param iam_server: the reference registered *IAM* server
    :param args: the arguments passed when requesting the service
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the user identification and token issued, or *None* if error
    """
    # initialize the return variable
    result: dict[str, str] | None = None

    # obtain the user's identification ant the token
    user_id: str = args.get("user-id") or args.get("login")
    user_token: str = args.get("access-token")

    err_msg: str | None = None
    if user_id:
        with _iam_lock:
            # retrieve the user data in the IAM server's registry
            user_data: dict[str, Any] = _get_user_data(iam_server=iam_server,
                                                       user_id=user_id,
                                                       errors=errors,
                                                       logger=logger)
            # retrieve the stored access token
            access_token: str = user_data[UserParam.ACCESS_TOKEN] if user_data else None
            if access_token:
                if access_token == user_token:
                    result = __retrieve_token(iam_server=iam_server,
                                              user_id=user_id,
                                              errors=errors,
                                              logger=logger)
                else:
                    err_msg = "Tokens do not match"
                    if logger:
                        logger.error(msg=err_msg)
            else:
                err_msg = f"User '{user_id}' not authenticated"
                if logger:
                    logger.error(msg=err_msg)
    else:
        err_msg = "User identification not provided"
        if logger:
            logger.error(msg=err_msg)

    if err_msg and isinstance(errors, list):
        errors.append(err_msg)

    return result


def iam_token(iam_server: IamServer,
              args: dict[str, Any],
              errors: list[str] = None,
              logger: Logger = None) -> dict[str, str]:
    """
    Retrieve the authentication token for the user, from *iam_server*.

    The user is identified by the attribute *user-id* or *login*, provided in *args*.

    On success, the returned *dict* will contain the following JSON:
        {
            "access-token": <token>,
            "user-id": <user-identification
        }

    :param iam_server: the reference registered *IAM* server
    :param args: the arguments passed when requesting the service
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the user identification and token issued, or *None* if error
    """
    # initialize the return variable
    result: dict[str, str] | None = None

    # obtain the user's identification ant the token
    user_id: str = args.get("user-id") or args.get("login")

    if user_id:
        with _iam_lock:
            result = __retrieve_token(iam_server=iam_server,
                                      user_id=user_id,
                                      errors=errors,
                                      logger=logger)
    else:
        msg: str = "User identification not provided"
        if logger:
            logger.error(msg=msg)
        if isinstance(errors, list):
            errors.append(msg)

    return result


def iam_callback(iam_server: IamServer,
                 args: dict[str, Any],
                 errors: list[str] = None,
                 logger: Logger = None) -> tuple[str, str] | None:
    """
    Entry point for the callback from *iam_server* via the front-end application, on authentication operations.

    The expected arguments in *args* are:
        - *state*: used to enhance security during the authorization process, typically to provide *CSRF* protection
        - *code*: the temporary authorization code provided by *iam_server*, to be exchanged for the token

    if *state* is postfixed with the string *#idp=<target-idp>*, this instructs *iam_server* to act as a broker,
    forwarding the authentication process to the *IAM* server *target-idp*. This mechanism fully dispenses with
    the flows 'callback-exchange', and 'callback' followed by 'exchange'.

    :param iam_server: the reference registered *IAM* server
    :param args: the arguments passed when requesting the service
    :param errors: incidental errors
    :param logger: optional logger
    :return: a tuple containing the reference user identification and the token obtained, or *None* if error
    """
    # initialize the return variable
    result: tuple[str, str] | None = None

    with _iam_lock:
        # retrieve the IAM server's data for all users
        users: dict[str, dict[str, Any]] = _get_iam_users(iam_server=iam_server,
                                                          errors=errors,
                                                          logger=logger) or {}
        # retrieve the OAuth2 state
        oauth_state: str = args.get("state")
        user_data: dict[str, Any] | None = None
        if oauth_state:
            for user, data in users.items():
                if user == oauth_state:
                    user_data = data
                    break

        # exchange 'code' received for the token
        if user_data:
            expiration: int = user_data["login-expiration"] or sys.maxsize
            if int(datetime.now(tz=TZ_LOCAL).timestamp()) > expiration:
                errors.append("Operation timeout")
            else:
                pos: int = oauth_state.rfind("_")
                target_idp: str = oauth_state[pos+1:] if pos > 0 else None
                target_iam: IamServer = IamServer(target_idp) if target_idp in IamServer else None
                target_data: dict[str, Any] = user_data.copy() if target_iam else None
                users.pop(oauth_state)
                code: str = args.get("code")
                header_data: dict[str, str] = {
                    "Content-Type": "application/x-www-form-urlencoded"
                }
                body_data: dict[str, Any] = {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": user_data.pop("redirect-uri")
                }
                now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
                token_data: dict[str, Any] = __post_for_token(iam_server=iam_server,
                                                              header_data=header_data,
                                                              body_data=body_data,
                                                              errors=errors,
                                                              logger=logger)
                # validate and store the token data
                if token_data:
                    result = __validate_and_store(iam_server=iam_server,
                                                  user_data=user_data,
                                                  token_data=token_data,
                                                  now=now,
                                                  errors=errors,
                                                  logger=logger)
                    if target_iam:
                        if logger:
                            logger.debug(msg=f"Requesting to IAM server '{iam_server}' "
                                             f"the token issued by '{target_iam}' ")
                        registry: dict[str, Any] = _get_iam_registry(iam_server,
                                                                     errors=errors,
                                                                     logger=logger)
                        url: str = (f"{registry[ServerParam.URL_BASE]}/realms/"
                                    f"{registry[ServerParam.CLIENT_REALM]}/broker/{target_idp}/token")
                        header_data: dict[str, str] = {
                            "Authorization": f"Bearer {result[1]}",
                            "Content-Type": "application/json"
                        }
                        token_data = __get_for_data(url=url,
                                                    header_data=header_data,
                                                    params=None,
                                                    errors=errors,
                                                    logger=logger)
                        if not errors:
                            token_info: tuple[str, str] = __validate_and_store(iam_server=target_iam,
                                                                               user_data=target_data,
                                                                               token_data=token_data,
                                                                               now=now,
                                                                               errors=errors,
                                                                               logger=logger)
                            if token_info and logger:
                                logger.debug(msg=f"Token obtained: {json.dumps(obj=token_info)}")
        else:
            msg: str = f"State '{oauth_state}' not found in {iam_server}'s registry"
            if logger:
                logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)

    return result


def iam_exchange(iam_server: IamServer,
                 args: dict[str, Any],
                 errors: list[str] = None,
                 logger: Logger = None) -> tuple[str, str]:
    """
    Request *iam_server* to issue a token in exchange for the token obtained from another *IAM* server.

    The expected parameters in *args* are:
        - user-id: identification for the reference user (alias: 'login')
        - token: the token to be exchanged

    The typical data set returned contains the following attributes:
        {
            "token_type": "Bearer",
            "access_token": <str>,
            "expires_in": <number-of-seconds>,
            "refresh_token": <str>,
            "refesh_expires_in": <number-of-seconds>
        }

    :param iam_server: the reference registered *IAM* server
    :param args: the arguments passed when requesting the service
    :param errors: incidental errors
    :param logger: optional logger
    :return: a tuple containing the reference user identification and the token obtained, or *None* if error
    """
    # initialize the return variable
    result: tuple[str, str] | None = None

    # make sure to have an errors list
    if not isinstance(errors, list):
        errors = []

    # obtain the user's identification
    user_id: str = args.get("user-id") or args.get("login")

    # obtain the token to be exchanged
    token: str = args.get("access-token")

    if user_id and token:
        token_issuer: str = jwt_get_claim(token=token,
                                          key="iss",
                                          errors=errors,
                                          logger=logger)
        if not errors:
            with _iam_lock:
                # retrieve the IAM server's registry
                client_id: str = _get_iam_property(iam_server=iam_server,
                                                   attr=ServerParam.CLIENT_ID,
                                                   errors=errors,
                                                   logger=logger)
                if client_id:
                    # make sure 'client_id' is linked to the token's 'token_sub' at the IAM server
                    __assert_link(iam_server=iam_server,
                                  user_id=user_id,
                                  token=token,
                                  token_issuer=token_issuer,
                                  errors=errors,
                                  logger=logger)
                    if not errors:
                        # exchange the token
                        if logger:
                            logger.debug(msg=f"Requesting the token exchange to IAM server '{iam_server}'")
                        header_data: dict[str, Any] = {
                            "Content-Type": "application/x-www-form-urlencoded"
                        }
                        body_data: dict[str, str] = {
                            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                            "subject_token": token,
                            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                            "audience": client_id,
                            "subject_issuer": token_issuer
                        }
                        now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
                        token_data: dict[str, Any] = __post_for_token(iam_server=iam_server,
                                                                      header_data=header_data,
                                                                      body_data=body_data,
                                                                      errors=errors,
                                                                      logger=logger)
                        # validate and store the token data
                        if not errors:
                            user_data: dict[str, Any] = {}
                            result = __validate_and_store(iam_server=iam_server,
                                                          user_data=user_data,
                                                          token_data=token_data,
                                                          now=now,
                                                          errors=errors,
                                                          logger=logger)
    else:
        msg: str = "User identification or token not provided"
        if logger:
            logger.debug(msg=msg)
        errors.append(msg)

    return result


def iam_userinfo(iam_server: IamServer,
                 args: dict[str, Any],
                 errors: list[str] = None,
                 logger: Logger = None) -> dict[str, Any] | None:
    """
    Obtain user data from *iam_server*.

    The user is identified by the attribute *user-id* or *login*, provided in *args*.

    :param iam_server: the reference registered *IAM* server
    :param args: the arguments passed when requesting the service
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the user information requested, or *None* if error
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    # obtain the user's identification
    user_id: str = args.get("user-id") or args.get("login")

    err_msg: str | None = None
    if user_id:
        with _iam_lock:
            # retrieve the IAM server's registry and the user data therein
            registry: dict[str, Any] = _get_iam_registry(iam_server,
                                                         errors=errors,
                                                         logger=logger)
            user_data: dict[str, Any] = registry[ServerParam.USERS].get(user_id)
            if user_data:
                url: str = (f"{registry[ServerParam.URL_BASE]}/realms/{registry[ServerParam.CLIENT_REALM]}"
                            "/protocol/openid-connect/userinfo")
                header_data: dict[str, str] = {
                    "Authorization": f"Bearer {args.get('access-token')}"
                }
                result = __get_for_data(url=url,
                                        header_data=header_data,
                                        params=None,
                                        errors=errors,
                                        logger=logger)
            else:
                err_msg = f"Unknown user '{user_id}'"
    else:
        err_msg: str = "User identification not provided"

    if err_msg:
        if logger:
            logger.error(msg=err_msg)
        if isinstance(errors, list):
            errors.append(err_msg)

    return result


def __assert_link(iam_server: IamServer,
                  user_id: str,
                  token: str,
                  token_issuer: str,
                  errors: list[str] | None,
                  logger: Logger | None) -> None:
    """
    Make sure *iam_server* has a link associating *user_id* to an internal user identification.

    This is a requirement for exchanging a token issued by a federated *IAM* server for an equivalent
    one from *iam_server*.

    :param iam_server: the reference *IAM* server
    :param user_id: the reference user identification
    :param token: the reference token
    :param errors: incidental errors
    :param logger: optional logger
    """
    # make sure to have an errors list
    if not isinstance(errors, list):
        errors = []

    if logger:
        logger.debug(msg="Verifying associations for user "
                         f"'{user_id}' in IAM server '{iam_server}'")
    # obtain a token with administrative rights
    admin_token: str = __get_administrative_token(iam_server=iam_server,
                                                  errors=errors,
                                                  logger=logger)
    if admin_token:
        registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                     errors=errors,
                                                     logger=logger)
        # obtain the internal user identification for 'user_id'
        if logger:
            logger.debug(msg="Obtaining internal identification "
                             f"for user '{user_id}' in IAM server '{iam_server}'")
        url: str = f"{registry[ServerParam.URL_BASE]}/admin/realms/{registry[ServerParam.CLIENT_REALM]}/users"
        header_data: dict[str, str] = {
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json"
        }
        params: dict[str, str] = {
            "username": user_id,
            "exact": "true"
        }
        users: list[dict[str, Any]] = __get_for_data(url=url,
                                                     header_data=header_data,
                                                     params=params,
                                                     errors=errors,
                                                     logger=logger)
        if not errors:
            # verify whether the IAM server that issued the token is a federated identity provider
            # in the associations between 'user_id' and the internal user identification
            internal_id: str = users[0].get("id")
            if logger:
                logger.debug(msg="Obtaining the providers federated in IAM server "
                                 f"'{iam_server}', for internal identification '{internal_id}'")
            url = (f"{registry[ServerParam.URL_BASE]}/admin/realms/"
                   f"{registry[ServerParam.CLIENT_REALM]}/users/{internal_id}/federated-identity")
            providers: list[dict[str, Any]] = __get_for_data(url=url,
                                                             header_data=header_data,
                                                             params=None,
                                                             errors=errors,
                                                             logger=logger)
            no_link: bool = True
            provider_name: str = _iam_server_from_issuer(issuer=token_issuer,
                                                         errors=errors,
                                                         logger=logger)
            if not errors:
                for provider in providers:
                    if provider.get("identityProvider") == provider_name:
                        no_link = False
                        break
                if no_link:
                    # link the identities
                    token_sub: str = jwt_get_claim(token=token,
                                                   key="sub",
                                                   errors=errors,
                                                   logger=logger)
                    if not errors:
                        if logger:
                            logger.debug(msg="Creating an association between identifications "
                                             f"'{user_id}' and '{token_sub}' in IAM server '{iam_server}'")
                        url += f"/{provider_name}"
                        json_data: dict[str, Any] = {
                            "userId": token_sub[0],
                            "userName": user_id
                        }
                        __post_json(url=url,
                                    header_data=header_data,
                                    json_data=json_data,
                                    errors=errors,
                                    logger=logger)


def __get_administrative_token(iam_server: IamServer,
                               errors: list[str] | None,
                               logger: Logger | None) -> str:
    """
    Obtain a token with administrative rights from *iam_server*'s reference realm.

    The reference realm is the realm specified at *iam_server*'s setup time. This operation requires
    the realm administrator's identification and secret password to have also been provided.

    :param iam_server: the reference *IAM* server
    :param errors: incidental errors
    :param logger: optional logger
    :return: a token with administrative rights for the reference realm
    """
    # initialize the return variable
    result: str | None = None

    if logger:
        logger.debug(msg="Requesting a token with "
                         f"administrative rights to IAM Server '{iam_server}'")

    # obtain the IAM server's registry
    registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                 errors=errors,
                                                 logger=logger)
    if registry:
        if registry[ServerParam.ADMIN_ID] and registry[ServerParam.ADMIN_SECRET]:
            header_data: dict[str, str] = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            body_data: dict[str, str] = {
                "grant_type": "password",
                "username": registry[ServerParam.ADMIN_ID],
                "password": registry[ServerParam.ADMIN_SECRET],
                "client_id": "admin-cli"
            }
            token_data: dict[str, Any] = __post_for_token(iam_server=iam_server,
                                                          header_data=header_data,
                                                          body_data=body_data,
                                                          errors=errors,
                                                          logger=logger)
            if token_data:
                # obtain the token
                result = token_data["access_token"]
                if logger:
                    logger.debug(msg="Administrative token obtained")

        elif logger or isinstance(errors, list):
            msg: str = ("Credentials for administrator of realm "
                        f"'{registry[ServerParam.CLIENT_REALM]}' "
                        f"at IAM server '{iam_server}' not provided")
            if logger:
                logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)

    elif logger or isinstance(errors, list):
        msg: str = f"Unknown IAM server {iam_server}"
        if logger:
            logger.error(msg=msg)
        if isinstance(errors, list):
            errors.append(msg)

    return result


def __get_client_secret(iam_server: IamServer,
                        errors: list[str] | None,
                        logger: Logger | None) -> str:
    """
    Retrieve the client's secret password.

    If it has not been provided at *iam_server*'s setup time, an attempt is made to obtain it
    from the *IAM* server itself. This would require the realm administrator's identification and
    secret password to have been provided, instead.

    :param iam_server: the reference *IAM* server
    :param errors: incidental errors
    :param logger: optional logger
     :return: the client's secret password, or *None* if error
    """
    # retrieve client's secret password stored in the IAM server's registry
    registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                 errors=errors,
                                                 logger=logger)
    result: str = registry[ServerParam.CLIENT_SECRET] if registry else None

    if not result and not errors:
        # obtain a token with administrative rights
        token: str = __get_administrative_token(iam_server=iam_server,
                                                errors=errors,
                                                logger=logger)
        if token:
            realm: str = registry[ServerParam.CLIENT_REALM]
            client_id: str = registry[ServerParam.CLIENT_ID]
            if logger:
                logger.debug(msg=f"Obtaining the UUID for client '{client_id}', "
                                 f"in realm '{realm}' at IAM server '{iam_server}'")
            # obtain the client UUID
            url: str = f"{registry[ServerParam.URL_BASE]}/realms/{realm}/clients"
            header_data: dict[str, str] = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            params: dict[str, str] = {
                "clientId": client_id
            }
            clients: list[dict[str, Any]] = __get_for_data(url=url,
                                                           header_data=header_data,
                                                           params=params,
                                                           errors=errors,
                                                           logger=logger)
            if clients:
                # obtain the client's secret password
                client_uuid: str = clients[0]["id"]
                if logger:
                    logger.debug(msg=f"Obtaining the secret for client UUID '{client_uuid}', "
                                     f"in realm '{realm}' at IAM server '{iam_server}'")
                url += f"/{client_uuid}/client-secret"
                reply: dict[str, Any] = __get_for_data(url=url,
                                                       header_data=header_data,
                                                       params=None,
                                                       errors=errors,
                                                       logger=logger)
                if reply:
                    # store the client's secret password and return it
                    result = reply["value"]
                    registry[ServerParam.CLIENT_ID] = result
    return result


def __get_for_data(url: str,
                   header_data: dict[str, str],
                   params: dict[str, Any] | None,
                   errors: list[str] | None,
                   logger: Logger | None) -> Any:
    """
    Send a *GET* request to *url* and return the data obtained.

    :param url: the target URL
    :param header_data: the data to send in the header of the request
    :param params: the query parameters to send in the request
    :param errors: incidental errors
    :param logger: optional logger
    :return: the data requested, or *None* if error
    """
    # initialize the return variable
    result: Any = None

    # log the GET
    if logger:
        logger.debug(msg=f"GET {url}, {json.dumps(obj=params,
                                                  ensure_ascii=False)}")
    try:
        response: requests.Response = requests.get(url=url,
                                                   headers=header_data,
                                                   params=params)
        if response.status_code == 200:
            # request succeeded
            result = response.json() or {}
            if logger:
                logger.debug(msg=f"GET success, {json.dumps(obj=result,
                                                            ensure_ascii=False)}")
        else:
            # request failed, report the problem
            msg: str = f"GET failure, status {response.status_code}, reason {response.reason}"
            if hasattr(response, "content") and response.content:
                msg += f", content '{response.content}'"
            if logger:
                logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)
    except Exception as e:
        # the operation raised an exception
        msg: str = exc_format(exc=e,
                              exc_info=sys.exc_info())
        if logger:
            logger.error(msg=msg)
        if isinstance(errors, list):
            errors.append(msg)

    return result


def __post_json(url: str,
                header_data: dict[str, str],
                json_data: dict[str, Any],
                errors: list[str] | None,
                logger: Logger | None) -> None:
    """
    Submit a *POST* request to *url*.

    :param header_data: the data to send in the header of the request
    :param json_data: the JSON data to send in the request
    :param errors: incidental errors
    :param logger: optional logger
    """
    # log the POST
    if logger:
        logger.debug(msg=f"POST {url}, {json.dumps(obj=json_data,
                                                   ensure_ascii=False)}")
    try:
        response: requests.Response = requests.post(url=url,
                                                    headers=header_data,
                                                    json=json_data)
        if response.status_code >= 400:
            # request failed, report the problem
            msg = f"POST failure, status {response.status_code}, reason {response.reason}"
            if hasattr(response, "content") and response.content:
                msg += f", content '{response.content}'"
            if logger:
                logger.error(msg=msg)
            if isinstance(errors, list):
                errors.append(msg)
        elif logger:
            logger.debug(msg="POST success")
    except Exception as e:
        # the operation raised an exception
        msg = exc_format(exc=e,
                         exc_info=sys.exc_info())
        if logger:
            logger.error(msg=msg)
        if isinstance(errors, list):
            errors.append(msg)


def __post_for_token(iam_server: IamServer,
                     header_data: dict[str, str],
                     body_data: dict[str, Any],
                     errors: list[str] | None,
                     logger: Logger | None) -> dict[str, Any] | None:
    """
    Send a *POST* request to *iam_server* and return the authentication token data obtained.

    For token acquisition, *body_data* will have the attributes:
        - "grant_type": "authorization_code"
        - "code": <16-character-random-code>
        - "redirect_uri": <redirect-uri>

    For token refresh, *body_data* will have the attributes:
        - "grant_type": "refresh_token"
        - "refresh_token": <current-refresh-token>

    For token exchange, *body_data* will have the attributes:
        - "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        - "subject_token": <token-to-be-exchanged>,
        - "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        - "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        - "audience": <client-id>,
        - "subject_issuer": "oidc"

    For administrative token acquisition, *body_data* will have the attributes:
        - "grant_type": "password"
        - "username": <realm-administrator-identification>
        - "password": <realm-administrator-secret>

    These attributes are then added to *body_data*, except for acquiring administrative tokens:
        - "client_id": <client-id>
        - "client_secret": <client-secret>

    If the operation is successful, the token data is stored in the *IAM* server's registry, and returned.
    Otherwise, *errors* will contain the appropriate error message.

    The typical data set returned contains the following attributes:
        {
            "token_type": "Bearer",
            "access_token": <str>,
            "expires_in": <number-of-seconds>,
            "refresh_token": <str>,
            "refesh_expires_in": <number-of-seconds>
        }

    :param iam_server: the reference registered *IAM* server
    :param header_data: the data to send in the header of the request
    :param body_data: the data to send in the body of the request
    :param errors: incidental errors
    :param logger: optional logger
    :return: the token data, or *None* if error
    """
    # initialize the return variable
    result: dict[str, Any] | None = None

    err_msg: str | None = None
    with _iam_lock:
        # retrieve the IAM server's registry
        registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                     errors=errors,
                                                     logger=logger)
        if registry:
            # complete the data to send in body of request
            if body_data["grant_type"] != "password":
                body_data["client_id"] = registry[ServerParam.CLIENT_ID]

            # build the URL
            url: str = (f"{registry[ServerParam.URL_BASE]}/realms/"
                        f"{registry[ServerParam.CLIENT_REALM]}/protocol/openid-connect/token")
            #  'client_secret' data must not be shown in log
            msg: str = f"POST {url}, {json.dumps(obj=body_data,
                                                 ensure_ascii=False)}"
            if body_data["grant_type"] != "password":
                # 'client_secret' not required for requesting tokens from staging environments
                client_secret: str = __get_client_secret(iam_server=iam_server,
                                                         errors=None,
                                                         logger=logger)
                if client_secret:
                    body_data["client_secret"] = client_secret
            # log the POST
            if logger:
                logger.debug(msg=msg)

            # obtain the token
            try:
                # typical return on a token request:
                # {
                #   "token_type": "Bearer",
                #   "access_token": <str>,
                #   "expires_in": <number-of-seconds>,
                #   "refresh_token": <str>,
                #   "refesh_expires_in": <number-of-seconds>
                # }
                response: requests.Response = requests.post(url=url,
                                                            headers=header_data,
                                                            data=body_data)
                if response.status_code == 200:
                    # request succeeded
                    result = response.json()
                    if logger:
                        logger.debug(msg=f"POST success, {json.dumps(obj=result,
                                                                     ensure_ascii=False)}")
                else:
                    # request failed, report the problem
                    err_msg = f"POST failure, status {response.status_code}, reason {response.reason}"
                    if hasattr(response, "content") and response.content:
                        err_msg += f", content '{response.content}'"
                    if logger:
                        logger.error(msg=err_msg)
            except Exception as e:
                # the operation raised an exception
                err_msg = exc_format(exc=e,
                                     exc_info=sys.exc_info())
                if logger:
                    logger.error(msg=err_msg)

    if err_msg and isinstance(errors, list):
        errors.append(err_msg)

    return result


def __retrieve_token(iam_server: IamServer,
                     user_id: str,
                     errors: list[str] | None,
                     logger: Logger | None) -> dict[str, str]:
    """
    Retrieve the token associated with *user_id* from the *IAM* registry.

    :param iam_server: the reference registered *IAM* server
    :param user_id: the identification for the user
    :param errors: incidental errors
    :param logger: optional logger
    :return: the token data, or *None* if error
    """
    # initialize the return variable
    result: dict[str, str] | None = None

    # retrieve the user data in the IAM server's registry
    user_data: dict[str, Any] = _get_user_data(iam_server=iam_server,
                                               user_id=user_id,
                                               errors=errors,
                                               logger=logger)
    # retrieve the stored access token
    access_token: str = user_data[UserParam.ACCESS_TOKEN] if user_data else None
    if access_token:
        # access token has expired
        refresh_token: str = user_data[UserParam.REFRESH_TOKEN]
        if refresh_token:
            access_expiration: int = user_data.get(UserParam.ACCESS_EXPIRATION)
            now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
            if now < access_expiration:
                # token has not expired, so return it
                result = {
                    "access-token": access_token,
                    "user-id": user_id
                }
            else:
                # access token has expired
                refresh_token: str = user_data[UserParam.REFRESH_TOKEN]
                if refresh_token:
                    refresh_expiration: int = user_data[UserParam.REFRESH_EXPIRATION]
                    if now < refresh_expiration:
                        header_data: dict[str, str] = {
                            "Content-Type": "application/x-www-form-urlencoded"
                        }
                        body_data: dict[str, str] = {
                            "grant_type": "refresh_token",
                            "refresh_token": refresh_token
                        }
                        now: int = int(datetime.now(tz=TZ_LOCAL).timestamp())
                        token_data: dict[str, Any] = __post_for_token(iam_server=iam_server,
                                                                      header_data=header_data,
                                                                      body_data=body_data,
                                                                      errors=errors,
                                                                      logger=logger)
                        # validate and store the token data
                        if token_data:
                            token_info: tuple[str, str] = __validate_and_store(iam_server=iam_server,
                                                                               user_data=user_data,
                                                                               token_data=token_data,
                                                                               now=now,
                                                                               errors=errors,
                                                                               logger=logger)
                            result = {
                                "access-token": token_info[1],
                                "user-id": user_id
                            }
                        else:
                            # refresh token is no longer valid
                            user_data[UserParam.REFRESH_TOKEN] = None
                    else:
                        # refresh token has expired
                        err_msg = "Access and refresh tokens expired"
                        if logger:
                            logger.error(msg=err_msg)
                else:
                    err_msg = "Access token expired, no refresh token available"
                    if logger:
                        logger.error(msg=err_msg)
    else:
        err_msg = f"User '{user_id}' not authenticated"
        if logger:
            logger.error(msg=err_msg)

    return result


def __validate_and_store(iam_server: IamServer,
                         user_data: dict[str, Any],
                         token_data: dict[str, Any],
                         now: int,
                         errors: list[str] | None,
                         logger: Logger) -> tuple[str, str] | None:
    """
    Validate and store the token data.

    The typical *token_data* contains the following attributes:
        {
            "token_type": "Bearer",
            "access_token": <str>,
            "expires_in": <number-of-seconds>,
            "refresh_token": <str>,
            "refesh_expires_in": <number-of-seconds>
        }

    :param iam_server: the reference registered *IAM* server
    :param user_data: the aurthentication data kepth in *iam_server*'s registry
    :param token_data: the token data
    :param errors: incidental errors
    :param logger: optional logger
    :return: tuple containing the user identification and the validated and stored token, or *None* if error
    """
    # initialize the return variable
    result: tuple[str, str] | None = None

    if logger:
        logger.debug(msg="Validating and storing the token")
    with _iam_lock:
        # retrieve the IAM server's registry
        registry: dict[str, Any] = _get_iam_registry(iam_server=iam_server,
                                                     errors=errors,
                                                     logger=logger)
        if registry:
            token: str = token_data.get("access_token")
            user_data["access-token"] = token
            # keep current refresh token if a new one is not provided
            if token_data.get("refresh_token"):
                user_data["refresh-token"] = token_data.get("refresh_token")
            user_data["access-expiration"] = now + token_data.get("expires_in")
            refresh_exp: int = user_data.get("refresh_expires_in")
            user_data["refresh-expiration"] = (now + refresh_exp) if refresh_exp else sys.maxsize
            public_key: str = _get_public_key(iam_server=iam_server,
                                              errors=errors,
                                              logger=logger)
            recipient_attr = registry[ServerParam.RECIPIENT_ATTR]
            login_id = user_data.pop("login-id", None)
            base_url: str = f"{registry[ServerParam.URL_BASE]}/realms/{registry[ServerParam.CLIENT_REALM]}"
            claims: dict[str, dict[str, Any]] = jwt_validate(token=token,
                                                             issuer=base_url,
                                                             recipient_id=login_id,
                                                             recipient_attr=recipient_attr,
                                                             public_key=public_key,
                                                             errors=errors,
                                                             logger=logger)
            if claims:
                users: dict[str, dict[str, Any]] = _get_iam_users(iam_server=iam_server,
                                                                  errors=errors,
                                                                  logger=logger)
                # must test with 'not errors'
                if not errors:
                    user_id: str = login_id if login_id else claims["payload"][recipient_attr]
                    users[user_id] = user_data
                    result = (user_id, token)
    return result
