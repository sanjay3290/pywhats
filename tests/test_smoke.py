"""Smoke tests: package imports, public API surface is stable."""

import pywhats
from pywhats import Client
from pywhats.events import JID


def test_version() -> None:
    assert pywhats.__version__


def test_client_construct() -> None:
    c = Client()
    assert c is not None


def test_jid_format() -> None:
    assert str(JID(user="15551234567")) == "15551234567@s.whatsapp.net"
    assert str(JID(user="15551234567", device=2)) == "15551234567.2@s.whatsapp.net"


def test_on_decorator_registers() -> None:
    c = Client()

    @c.on("qr")
    async def _h(qr: str) -> None:
        pass

    assert len(c._handlers["qr"]) == 1
