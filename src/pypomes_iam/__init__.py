from .jusbr_pomes import (
    jusbr_setup, jusbr_get_token, jusbr_set_scope
)
from .keycloak_pomes import (
    keycloak_setup, keycloak_get_token, keycloak_set_scope
)
from .provider_pomes import (
    provider_register, provider_get_token
)
from .token_pomes import (
    token_validate
)

__all__ = [
    # jusbr_pomes
    "jusbr_setup", "jusbr_get_token", "jusbr_set_scope",
    # keycloak_pomes
    "keycloak_setup", "keycloak_get_token", "keycloak_set_scope",
    # provider_pomes
    "provider_register", "provider_get_token",
    # token_pomes
    "token_validate"
]

from importlib.metadata import version
__version__ = version("pypomes_iam")
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())
