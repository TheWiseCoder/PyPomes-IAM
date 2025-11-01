import jwt
import sys
from jwt import PyJWK
from jwt.algorithms import RSAPublicKey
from logging import Logger
from pypomes_core import exc_format
from typing import Any


def token_get_claims(token: str,
                     errors: list[str] = None,
                     logger: Logger = None) -> dict[str, dict[str, Any]] | None:
    """
    Retrieve the claims set of a JWT *token*.

    Any well-constructed JWT token may be provided in *token*.
    Note that neither the token's signature nor its expiration is verified.

    :param token: the refrence token
    :param errors: incidental error messages
    :param logger: optional logger
    :return: the token's claimset, or *None* if error
    """
    # initialize the return variable
    result: dict[str, dict[str, Any]] | None = None

    if logger:
        logger.debug(msg="Retrieve claims for token")

    try:
        header: dict[str, Any] = jwt.get_unverified_header(jwt=token)
        payload: dict[str, Any] = jwt.decode(jwt=token,
                                             options={"verify_signature": False})
        result = {
            "header": header,
            "payload": payload
        }
    except Exception as e:
        exc_err: str = exc_format(exc=e,
                                  exc_info=sys.exc_info())
        if logger:
            logger.error(msg=f"Error retrieving the token's claims: {exc_err}")
        if isinstance(errors, list):
            errors.append(exc_err)

    return result


def token_validate(token: str,
                   issuer: str = None,
                   recipient_id: str = None,
                   recipient_attr: str = None,
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

    The parameters *recipient_id* and *recipient_attr* refer the token's expected subject, respectively,
    the subject's identification and the attribute in the token's payload data identifying its subject.
    If both are provided, *recipient_id* is validated.

    On failure, *errors* will contain the reason(s) for rejecting *token*.
    On success, return the token's claims (*header* and *payload*).

    :param token: the token to be validated
    :param public_key: optional public key used to sign the token, in *PEM* format
    :param issuer: optional value to compare with the token's *iss* (issuer) attribute in its *payload*
    :param recipient_id: identification of the expected token subject
    :param recipient_attr: attribute in the token's payload holding the expected subject's identification
    :param errors: incidental error messages
    :param logger: optional logger
    :return: The token's claims (*header* and *payload*), or *None* if error
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
        require: list[str] = ["exp", "iat"]
        if issuer:
            require.append("iss")
        options: dict[str, Any] = {
            "require": require,
            "verify_aud": False,
            "verify_exp": True,
            "verify_iat": True,
            "verify_iss": issuer is not None,
            "verify_nbf": False,
            "verify_signature": token_alg in ["RS256", "RS512"] and public_key is not None
        }
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
            if recipient_id and recipient_attr and \
                    payload.get(recipient_attr) and recipient_id != payload.get(recipient_attr):
                msg: str = f"Token was issued to '{payload.get(recipient_attr)}', not to '{recipient_id}'"
                if logger:
                    logger.error(msg=msg)
                errors.append(msg)
            else:
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
