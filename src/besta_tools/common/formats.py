from __future__ import annotations

from typing import cast, TYPE_CHECKING
if TYPE_CHECKING:
    from construct_typed import Context

from dataclasses import dataclass
from construct import (
    Check,
    Int16ul,
    Rebuild,
    this
)
from construct_typed import DataclassMixin, DataclassStruct, csfield, csfield_noinit


def _inv_u16_per_byte(ctx: Context) -> int:
    value = cast(int, ctx.checksum)
    lo = value & 0xff
    hi = (value >> 8) & 0xff
    return (((0x100 - hi) & 0xff) << 8) | ((0x100 - lo) & 0xff)


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
