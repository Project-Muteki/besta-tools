import dataclasses
from construct import Array, Byte, Const, Int16ul, Int32ul, this
from construct_typed import DataclassMixin, DataclassStruct, EnumBase, TEnum, csfield

from ..common.formats import CsChecksumValue, ChecksumValue


class RomType(EnumBase):
    DATA_BOOK = 0x8
    DATA_DICT = 0x9
    APPLET_GAME = 0xb
    APPLET_TOOL = 0x11
    APPLET_STUDY = 0x16


CsRomType = TEnum(Int16ul, RomType)


class RomLocale(EnumBase):
    NONE = 0x0
    ZH_CN = 0x1
    ZH_TW = 0x2
    JA_JP = 0x4
    KO_KR = 0x8
    TH_TH = 0x10
    EN_US = 0x1000
    FORCE_UTF16 = 0x8000


CsRomLocale = TEnum(Int16ul, RomLocale)


class MagicType(EnumBase):
    APPLET = (ord('I') | (ord('F') << 8)) & 0xffff
    DATA = (ord('M') | (ord('F') << 8)) & 0xffff


@dataclasses.dataclass
class RomSpecType(DataclassMixin):
    magic: int = csfield(Int16ul)
    spec_size: int = csfield(Const(0x80, Int16ul))
    type: RomType = csfield(CsRomType)
    checksum: ChecksumValue = csfield(CsChecksumValue)
    unk_0xa: int = csfield(Int16ul)
    default_locale: int = csfield(CsRomLocale)
    sections_offset: int = csfield(Int16ul)


@dataclasses.dataclass
class RomExecutableHeaderType(DataclassMixin):
    header_size: int = csfield(Const(0x80, Int16ul))
    code_size: int = csfield(Int32ul)
    unk_0x8: int = csfield(Int32ul)
    unk_0xc: int = csfield(Int32ul)
    unk_0x10: int = csfield(Int32ul)
    unk_0x14: int = csfield(Int32ul)
    unk_0x18: int = csfield(Int32ul)
    unk_0x1c: int = csfield(Int32ul)
    unk_0x20: int = csfield(Int32ul)
    unk_0x24: int = csfield(Int32ul)
    arch: int = csfield(Byte)
    unk_0x29: int = csfield(Byte)
    unk_0x2a: int = csfield(Int16ul)
    _reserved: list[int] = csfield(Array(21, Int32ul))
