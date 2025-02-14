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
class RomSpecTimestamp(DataclassMixin):
    year: int = csfield(Int16ul)
    month: int = csfield(Int16ul)
    day: int = csfield(Int16ul)
    hour: int = csfield(Int16ul)
    minute: int = csfield(Int16ul)
    second: int = csfield(Int16ul)


CsRomSpecTimestamp = DataclassStruct(RomSpecTimestamp)


@dataclasses.dataclass
class RomSpecType(DataclassMixin):
    magic: int = csfield(Int16ul)
    spec_size: int = csfield(Const(0x80, Int16ul))
    type: RomType = csfield(CsRomType)
    checksum: ChecksumValue = csfield(CsChecksumValue)
    unk_0xa: int = csfield(Int16ul)
    default_locale: int = csfield(CsRomLocale)
    sections_offset: int = csfield(Int16ul)
    build_timestamp: RomSpecTimestamp = csfield(CsRomSpecTimestamp)
    rom_size: int = csfield(Int32ul)
    entry_point: int = csfield(Int32ul)
    fallback_title_offset: int = csfield(Int32ul)
    copyright_offset: int = csfield(Int32ul)
    icon_offset: int = csfield(Int32ul)
    version_offset: int = csfield(Int32ul)
    data_offset: int = csfield(Int32ul)
    sdk_id_offset: int = csfield(Int32ul)
    unk_0x3c: int = csfield(Int32ul)
    unk_0x40: int = csfield(Int32ul)
    type_str_offset: int = csfield(Int32ul)
    unk_0x48: int = csfield(Int32ul)
    unk_0x4c: int = csfield(Int16ul)
    unk_0x4e: int = csfield(Int16ul)
    localized_title_offset: int = csfield(Int32ul)
    unk_0x54: int = csfield(Int32ul)
    unk_0x58: int = csfield(Int32ul)
    subtype: int = csfield(Int32ul)
    unk_0x60: int = csfield(Int32ul)
    unk_0x64: list[int] = csfield(Array(7, Int32ul))


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
