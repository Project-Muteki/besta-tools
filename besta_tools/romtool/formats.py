import dataclasses
import datetime

from construct import Byte, Const, Default, Int16ul, Int32ul, this
from construct_typed import DataclassMixin, DataclassStruct, EnumBase, TEnum, FlagsEnumBase, TFlagsEnum, csfield

from ..common.formats import CsChecksumValue, ChecksumValue


class RomType(FlagsEnumBase):
    DATA_BOOK = 0x8
    DATA_DICT = 0x9
    APPLET_GAME = 0xb
    APPLET_TOOL = 0x11
    APPLET_STUDY = 0x16


CsRomType = TFlagsEnum(Int16ul, RomType)


class RomLocale(FlagsEnumBase):
    NONE = 0x0
    ZH_CN = 0x1
    ZH_TW = 0x2
    JA_JP = 0x4
    KO_KR = 0x8
    TH_TH = 0x10
    EN_US = 0x1000
    FORCE_UTF16 = 0x8000
    UNSET = 0xffff


CsRomLocale = TFlagsEnum(Int16ul, RomLocale)


class MagicType(EnumBase):
    APPLET = (ord('I') | (ord('F') << 8)) & 0xffff
    DATA = (ord('M') | (ord('F') << 8)) & 0xffff


CsMagicType = TEnum(Int16ul, MagicType)


@dataclasses.dataclass
class RomSpecTimestamp(DataclassMixin):
    year: int = csfield(Int16ul)
    month: int = csfield(Int16ul)
    day: int = csfield(Int16ul)
    hour: int = csfield(Int16ul)
    minute: int = csfield(Int16ul)
    second: int = csfield(Int16ul)

    @classmethod
    def from_date(cls, date: datetime.datetime):
        return cls(
            year=date.year,
            month=date.month,
            day=date.day,
            hour=date.hour,
            minute=date.minute,
            second=date.second,
        )

    @classmethod
    def now(cls):
        now = datetime.datetime.now(tz=datetime.UTC)
        return cls.from_date(now)


CsRomSpecTimestamp = DataclassStruct(RomSpecTimestamp)


@dataclasses.dataclass
class RomSpecType(DataclassMixin):
    magic: int = csfield(CsMagicType)
    spec_size: int = csfield(Const(0x80, Int16ul))
    type_: RomType | int = csfield(Int16ul)  # Intentionally set this to be not an enum so we can pass an int as type
    checksum: ChecksumValue = csfield(CsChecksumValue)
    unk_0xa: int = csfield(Default(Int16ul, 0xffff))
    default_locale: RomLocale = csfield(CsRomLocale)
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
    unk_0x3c: int = csfield(Default(Int32ul, 0xffffffff))
    unk_0x40: int = csfield(Default(Int32ul, 0xffffffff))
    ext_metadata_offset: int = csfield(Int32ul)
    unk_0x48: int = csfield(Default(Int32ul, 0xffffffff))
    unk_0x4c: int = csfield(Default(Int16ul, 0xffff))
    unk_0x4e: int = csfield(Default(Int16ul, 0xffff))
    localized_title_offset: int = csfield(Int32ul)
    unk_0x54: int = csfield(Default(Int32ul, 0xffffffff))
    unk_0x58: int = csfield(Default(Int32ul, 0xffffffff))
    subtype: int = csfield(Int32ul)
    unk_0x60: int = csfield(Default(Int32ul, 0xffffffff))
    unk_0x64: list[int] = csfield(Default(Int32ul[7], tuple([0xffffffff] * 7)))


CsRomSpecType = DataclassStruct(RomSpecType)


@dataclasses.dataclass
class RomFallbackTitle(DataclassMixin):
    unk_0x0: int = csfield(Default(Int16ul, 0xffff))
    locale: RomLocale = csfield(CsRomLocale)
    title_offset: int = csfield(Int32ul)
    chinese_title_offset: int = csfield(Int32ul)
    short_title_offset: int = csfield(Int32ul)
    chinese_short_title_offset: int = csfield(Int32ul)


CsRomFallbackTitle = DataclassStruct(RomFallbackTitle)


@dataclasses.dataclass
class RomExtMetadataHeader(DataclassMixin):
    unk_0x0: list[int] = csfield(Default(Int32ul[5], tuple([0xffffffff] * 5)))
    num_localized_title_entries: int = csfield(Int32ul)
    unk_0x18: list[int] = csfield(Default(Int32ul[3], tuple([0xffffffff] * 3)))


CsRomExtMetadataHeader = DataclassStruct(RomExtMetadataHeader)


@dataclasses.dataclass
class RomLocalizedTitle(DataclassMixin):
    num_entries: int = csfield(Int32ul)
    locale: RomLocale = csfield(CsRomLocale)
    unk_0x6: int = csfield(Default(Int16ul, 0x0))
    unk_0x8: int = csfield(Default(Int32ul, 0xffffffff))
    unk_0xc: int = csfield(Default(Int32ul, 0xffffffff))


CsRomLocalizedTitle = DataclassStruct(RomLocalizedTitle)


@dataclasses.dataclass
class RomLocalizedTitleEntry(DataclassMixin):
    locale: RomLocale = csfield(CsRomLocale)
    unk_0x2: int = csfield(Default(Int16ul, 0x0))
    unk_0x4: int = csfield(Default(Int32ul, 0xffffffff))
    title_offset: int = csfield(Int32ul)
    short_title_offset: int = csfield(Int32ul)
    unk_0x10: int = csfield(Default(Int32ul, 0xffffffff))
    unk_0x14: int = csfield(Default(Int32ul, 0xffffffff))
    unk_0x18: int = csfield(Default(Int32ul, 0xffffffff))
    unk_0x1c: int = csfield(Default(Int32ul, 0xffffffff))


CsRomLocalizedTitleEntry = DataclassStruct(RomLocalizedTitleEntry)


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
    _reserved: list[int] = csfield(Int32ul[21])
