import importlib


def patch_filetype() -> None:
    m = importlib.import_module('filetype.utils')
    setattr(m, '_NUM_SIGNATURE_BYTES', 65536)


patch_filetype()


from collections.abc import Sequence
from typing import Final, override

import re

from filetype.types import Type


# MIME/Media Type guidelines:
#
# Generally the Media Types here should follow IANA Media Types:
# https://www.iana.org/assignments/media-types/media-types.xhtml.
# If nothing from the above properly describes the type, use XDG MIME info:
# https://gitlab.freedesktop.org/xdg/shared-mime-info/-/blob/master/data/freedesktop.org.xml.in
# If neither of these properly describe the type, use the most commonly used one (from e.g. libmagic).
# If everything fails, or if the format is specific to Besta to begin with, make a custom Media Type.
# Custom Media Types specific to Besta should follow the application/vnd.besta.* format.


class Ini(Type):
    MIME: Final = 'application/x-wine-extension-ini'
    EXTENSION: Final = 'ini'
    SECTION: Final = re.compile(br'\[[A-Za-z0-9]+\]\s*(?:;.*)?\r\n')

    def __init__(self) -> None:
        super().__init__(self.MIME, self.EXTENSION)

    @override
    def match(self, buf: bytes | bytearray) -> bool:
        # TODO: libmagic uses a multi-step approach to also detect autorun.inf, etc.
        # Should we do something similar?
        # At least unit.ini should be automatically detected.
        return self.SECTION.search(buf) is not None


class UnitIni(Type):
    MIME: Final = 'application/vnd.besta.unit-ini'
    EXTENSION: Final = 'ini'
    SECTION: Final = re.compile(br'\[(?:PIMSaveDir|Max_Rec|FixedCateNum|Total|interfacelang|CateInfo|StartUp|MacInfo)\]\s*(?:;.*)?\r\n')

    def __init__(self) -> None:
        super().__init__(self.MIME, self.EXTENSION)

    @override
    def match(self, buf: bytes | bytearray) -> bool:
        # TODO: libmagic uses a multi-step approach to also detect autorun.inf, etc.
        # Should we do something similar?
        # At least unit.ini should be automatically detected.
        return self.SECTION.search(buf) is not None


class PxBundle(Type):
    MIME: Final = 'application/vnd.besta.px-bundle'
    EXTENSION: Final = 'pxbundle'

    def __init__(self) -> None:
        super().__init__(self.MIME, self.EXTENSION)
    
    @override
    def match(self, buf: bytes | bytearray) -> bool:
        offset = int.from_bytes(buf[:4], 'little')
        if offset == 0 or offset > len(buf) or offset + 2 > len(buf):
            return False
        px = buf[offset:offset+2]
        if px == b'PX':
            return True
        return False


class FatX(Type):
    MIME: Final = 'application/vnd.efi.img'
    EXTENSION: Final = 'img'

    def __init__(self) -> None:
        super().__init__(self.MIME, self.EXTENSION)

    @override
    def match(self, buf: bytes | bytearray) -> bool:
        if len(buf) < 512:
            return False
        if buf[510:512] != b'\x55\xaa':
            return False
        # TODO more robust checks
        if buf[0x52:0x5a] in (b'FAT32   ', b'FAT16   '):
            return True
        return False


class Iso9660(Type):
    MIME: Final = 'application/vnd.efi.iso'
    EXTENSION: Final = 'iso'

    def __init__(self) -> None:
        super().__init__(self.MIME, self.EXTENSION)

    @override
    def match(self, buf: bytes | bytearray) -> bool:
        if len(buf) < 0x8800:
            return False
        if buf[0x8001:0x8007] != b'CD001\x01':
            return False
        return True


TYPES: Sequence[Type] = (
    FatX(),
    Iso9660(),
    PxBundle(),
    Ini(),
    UnitIni(),  # Must be matched before the Ini checker. Custom types are matched in the REVERSE insertion order.
)
