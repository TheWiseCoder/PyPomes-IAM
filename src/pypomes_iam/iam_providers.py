import requests
import sys
from base64 import b64encode
from datetime import datetime
from logging import Logger
from pypomes_core import TZ_LOCAL, exc_format
from typing import Any

# structure:
# {
#    <provider-id>: {
#      "url": <strl>,
#      "user": <str>,
#      "pwd": <str>,
#      "basic-auth": <bool>,
#      "headers-data": <dict[str, str]>,
#      "body-data": <dict[str, str],
#      "token": <str>,
#      "expiration": <timestamp>
#    }
# }
_provider_registry: dict[str, dict[str, Any]] = {}


def provider_register(provider_id: str,
                      access_url: str,
                      auth_user: str,
                      auth_pwd: str,
                      custom_auth: tuple[str, str] = None,
                      headers_data: dict[str, str] = None,
                      body_data: dict[str, str] = None) -> None:
    """
    Register an external authentication token provider.

    If specified, *custom_auth* provides key names for sending credentials (username and password, in this order)
    as key-value pairs in the body of the request. Otherwise, the external provider *provider_id* uses the standard
    HTTP Basic Authorization scheme, wherein the credentials are B64-encoded and sent in the request headers.

    Optional constant key-value pairs (such as ['Content-Type', 'application/x-www-form-urlencoded']), to be
    added to the request headers, may be specified in *headers_data*. Likewise, optional constant key-value pairs
    (such as ['grant_type', 'client_credentials']), to be added to the request body, may be specified in *body_data*.

    :param provider_id: the provider's identification
    :param access_url: the url to request authentication tokens with
    :param auth_user: the basic authorization user
    :param auth_pwd: the basic authorization password
    :param custom_auth: optional key names for sending the credentials as key-value pairs in the body of the request
    :param headers_data: optional key-value pairs to be added to the request headers
    :param body_data: optional key-value pairs to be added to the request body
    """
    global _provider_registry  # noqa: PLW0602
    _provider_registry[provider_id] = {
        "url": access_url,
        "user": auth_user,
        "pwd": auth_pwd,
        "custom-auth": custom_auth,
        "headers-data": headers_data,
        "body-data": body_data,
        "token": None,
        "expiration": datetime.now(tz=TZ_LOCAL).timestamp()
    }


def provider_get_token(provider_id: str,
                       errors: list[str] = None,
                       logger: Logger = None) -> str | None:
    """
    Obtain an authentication token from the external provider *provider_id*.

    :param provider_id: the provider's identification
    :param errors: incidental error messages
    :param logger: optional logger
    """
    # initialize the return variable
    result: str | None = None

    global _provider_registry  # noqa: PLW0602
    err_msg: str | None = None
    provider: dict[str, Any] = _provider_registry.get(provider_id)
    if provider:
        now: float = datetime.now(tz=TZ_LOCAL).timestamp()
        if now > provider.get("expiration"):
            user: str = provider.get("user")
            pwd: str = provider.get("pwd")
            headers_data: dict[str, str] = provider.get("headers-data") or {}
            body_data: dict[str, str] = provider.get("body-data") or {}
            custom_auth: tuple[str, str] = provider.get("custom-auth")
            if custom_auth:
                body_data[custom_auth[0]] = user
                body_data[custom_auth[1]] = pwd
            else:
                enc_bytes: bytes = b64encode(f"{user}:{pwd}".encode())
                headers_data["Authorization"] = f"Basic {enc_bytes.decode()}"
            url: str = provider.get("url")
            try:
                # typical return on a token request:
                # {
                #   "token_type": "Bearer",
                #   "access_token": <str>,
                #   "expires_in": <number-of-seconds>,
                #   optional data:
                #   "refresh_token": <str>,
                #   "refresh_expires_in": <number-of-seconds>
                # }
                response: requests.Response = requests.post(url=url,
                                                            data=body_data,
                                                            headers=headers_data,
                                                            timeout=None)
                if response.status_code < 200 or response.status_code >= 300:
                    # request resulted in error, report the problem
                    err_msg = (f"POST '{url}': failed, "
                               f"status {response.status_code}, reason '{response.reason}'")
                else:
                    reply: dict[str, Any] = response.json()
                    provider["token"] = reply.get("access_token")
                    provider["expiration"] = now + int(reply.get("expires_in"))
                    if logger:
                        logger.debug(msg=f"POST '{url}': status {response.status_code}")
            except Exception as e:
                # the operation raised an exception
                err_msg = exc_format(exc=e,
                                     exc_info=sys.exc_info())
                err_msg = f"POST '{url}': error, '{err_msg}'"
    else:
        err_msg: str = f"Provider '{provider_id}' not registered"

    if err_msg:
        if isinstance(errors, list):
            errors.append(err_msg)
        if logger:
            logger.error(msg=err_msg)
    else:
        result = provider.get("token")

    return result


