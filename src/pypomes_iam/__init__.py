from iam_jusbr import (
    jusbr_setup, jusbr_get_token
)
from .iam_provider import (
    provider_register, provider_get_token
)

__all__ = [
    # iam_jusbr
    "jusbr_setup", "jusbr_get_token",
    # jwt_provider
    "provider_register", "provider_get_token"
]

from importlib.metadata import version
__version__ = version("pypomes_iam")
__version_info__ = tuple(int(i) for i in __version__.split(".") if i.isdigit())
