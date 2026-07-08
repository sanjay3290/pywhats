"""Exception hierarchy for pywhats."""


class PyWhatsError(Exception):
    """Base class for all pywhats errors."""


class NotConnected(PyWhatsError):
    """Raised when an operation requires an active connection."""


class ConnectionClosed(PyWhatsError):
    """Raised when the underlying socket closes unexpectedly."""


class PairingFailed(PyWhatsError):
    """Raised when the QR pairing flow does not complete."""


class HandshakeError(PyWhatsError):
    """Raised when the Noise handshake fails."""


class DecodeError(PyWhatsError):
    """Raised when a received binary node cannot be decoded."""
