from __future__ import annotations

from typing import cast, TYPE_CHECKING
if TYPE_CHECKING:
    from construct import Context, Construct, ListContainer

import dataclasses
from construct import (
    Check,
    Default,
    Int16ul,
    Rebuild,
    this
)
from construct_typed import DataclassMixin, DataclassStruct, csfield


def _inv_u16_per_byte(ctx: 'Context') -> int:
    value = cast(int, ctx.checksum)
    lo = value & 0xff
    hi = (value >> 8) & 0xff
    return (((0x100 - hi) & 0xff) << 8) | ((0x100 - lo) & 0xff)


@dataclasses.dataclass
class ChecksumValue(DataclassMixin):
    checksum: int = csfield(Int16ul)
    checksum_byteinv: int = csfield(Rebuild(Int16ul, _inv_u16_per_byte))
    _integrity: None = csfield(Check(
        (
            (this.checksum & 0xff) +
            (this.checksum_byteinv & 0xff) +
            ((this.checksum >> 8) & 0xff) +
            ((this.checksum_byteinv >> 8) & 0xff)
        ) & 0xff == 0
    ))


CsChecksumValue = DataclassStruct(ChecksumValue)

# The type definition here for Default is wrong. Default accepts a tuple as a default value for list
# but the type indicates that it only accepts a list.
# Cast to Any for now to disable type checking.
def ArrayDefault[T](subcon: Construct[ListContainer[T], list[T]], value: tuple[T, ...]) -> Default[ListContainer[T], list[T]]:
    return Default(subcon, cast(list[T], value))
