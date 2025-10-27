import jwt
import sys
from jwt import PyJWK
from jwt.algorithms import RSAPublicKey
from logging import Logger
from pypomes_core import exc_format
from typing import Any


def token_validate(token: str,
                   issuer: str = None,
                   public_key: str | bytes | PyJWK | RSAPublicKey = None,
                   errors: list[str] = None,
                   logger: Logger = None) -> dict[str, dict[str, Any]] | None:
    """
    Verify whether *token* is a valid JWT token, and return its claims (sections *header* and *payload*).

    The supported public key types are:
        - *DER*: Distinguished Encoding Rules (bytes)
        - *PEM*: Privacy-Enhanced Mail (str)
        - *PyJWK*: a formar from the *PyJWT* package
        - *RSAPublicKey*: a format from the *PyJWT* package

    If an asymmetric algorithm was used to sign the token and *public_key* is provided, then
    the token is validated, by using the data in its *signature* section.

    On failure, *errors* will contain the reason(s) for rejecting *token*.
    On success, return the token's claims (*header* and *payload*).

    :param token: the token to be validated
    :param public_key: optional public key used to sign the token, in *PEM* format
    :param issuer: optional value to compare with the token's *iss* (issuer) attribute in its *payload*
    :param errors: incidental error messages
    :param logger: optional logger
    :return: The token's claims (*header* and *payload*) if it is valid, *None* otherwise
    """
    # initialize the return variable
    result: dict[str, dict[str, Any]] | None = None

    if logger:
        logger.debug(msg="Validate JWT token")

    # make sure to have an errors list
    if not isinstance(errors, list):
        errors = []

    # extract needed data from token header
    token_header: dict[str, Any] | None = None
    try:
        token_header: dict[str, Any] = jwt.get_unverified_header(jwt=token)
    except Exception as e:
        exc_err: str = exc_format(exc=e,
                                  exc_info=sys.exc_info())
        if logger:
            logger.error(msg=f"Error retrieving the token's header: {exc_err}")
        errors.append(exc_err)

    # validate the token
    if not errors:
        token_alg: str = token_header.get("alg")
        options: dict[str, Any] = {
            "require": ["exp", "iat"],
            "verify_aud": False,
            "verify_exp": True,
            "verify_iat": True,
            "verify_iss": issuer is not None,
            "verify_nbf": False,
            "verify_signature": token_alg in ["RS256", "RS512"] and public_key is not None
        }
        if issuer:
            options["require"].append("iss")
        try:
            # raises:
            #   InvalidTokenError: token is invalid
            #   InvalidKeyError: authentication key is not in the proper format
            #   ExpiredSignatureError: token and refresh period have expired
            #   InvalidSignatureError: signature does not match the one provided as part of the token
            #   ImmatureSignatureError: 'nbf' or 'iat' claim represents a timestamp in the future
            #   InvalidAlgorithmError: the specified algorithm is not recognized
            #   InvalidIssuedAtError: 'iat' claim is non-numeric
            #   MissingRequiredClaimError: a required claim is not contained in the claimset
            payload: dict[str, Any] = jwt.decode(jwt=token,
                                                 key=public_key,
                                                 algorithms=[token_alg],
                                                 options=options,
                                                 issuer=issuer)
            result = {
                "header": token_header,
                "payload": payload
            }
        except Exception as e:
            exc_err: str = exc_format(exc=e,
                                      exc_info=sys.exc_info())
            if logger:
                logger.error(msg=f"Error decoding the token: {exc_err}")
            errors.append(exc_err)

    if not errors and logger:
        logger.debug(msg="Token is valid")

    return result
