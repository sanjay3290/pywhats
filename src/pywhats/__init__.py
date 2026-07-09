"""pywhats — async Python client for the WhatsApp multi-device protocol."""

from pywhats.client import Client
from pywhats.errors import ConnectionClosed, NotConnected, PairingFailed, PyWhatsError

__version__ = "0.1.0"

__all__ = [
    "Client",
    "ConnectionClosed",
    "NotConnected",
    "PairingFailed",
    "PyWhatsError",
    "__version__",
]
