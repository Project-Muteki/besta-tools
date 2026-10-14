from __future__ import annotations

from typing import Final, cast, TYPE_CHECKING
if TYPE_CHECKING:
    from construct_typed import Context

from dataclasses import dataclass
from construct import (
    Check,
    Int16ul,
    Rebuild,
    this
)
from construct_typed import DataclassMixin, DataclassStruct, FlagsEnumBase, TFlagsEnum, csfield, csfield_noinit


def _inv_u16_per_byte(ctx: Context) -> int:
    value = cast(int, ctx.checksum)
    lo = value & 0xff
    hi = (value >> 8) & 0xff
    return (((0x100 - hi) & 0xff) << 8) | ((0x100 - lo) & 0xff)


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


LOCALE_MAPPING: Final[dict[str, RomLocale]] = {
    'zh_CN': RomLocale.ZH_CN,
    'zh_TW': RomLocale.ZH_TW,
    'ja': RomLocale.JA_JP,
    'ko': RomLocale.KO_KR,
    'th': RomLocale.TH_TH,
    'en': RomLocale.EN_US,
}


@dataclass
class ChecksumValue(DataclassMixin):
    checksum: int = csfield(Int16ul)
    checksum_byteinv: int | None = csfield_noinit(Rebuild(Int16ul, _inv_u16_per_byte))
    _integrity: None = csfield_noinit(Check(
        (
            (this.checksum & 0xff) +
            (this.checksum_byteinv & 0xff) +
            ((this.checksum >> 8) & 0xff) +
            ((this.checksum_byteinv >> 8) & 0xff)
        ) & 0xff == 0
    ))


CsChecksumValue = DataclassStruct(ChecksumValue)
