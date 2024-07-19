import dataclasses
import typing as t
from construct import Array, Byte, Const, Int16ul, Int32ul, this
from construct_typed import DataclassMixin, DataclassStruct, EnumBase, TEnum, csfield

from ..common.formats import CsChecksumValue, ChecksumValue


class ROMType(EnumBase):
    DATA_BOOK = 0x8
    DATA_DICT = 0x9
    APPLET_GAME = 0xb
    APPLET_TOOL = 0x11
    APPLET_STUDY = 0x16


class MagicType(EnumBase):
    APPLET = (ord('I') | (ord('F') << 8)) & 0xffff
    DATA = (ord('M') | (ord('F') << 8)) & 0xffff


@dataclasses.dataclass
class ROMSpecType(DataclassMixin):
    magic: int = csfield(Int16ul)
    header_size: int = csfield(Const(0x80, Int16ul))
    type: ROMType = csfield(TEnum(Int16ul, ROMType))
    checksum: ChecksumValue = csfield(CsChecksumValue)
    unk_0xa: int = csfield(Int16ul)
    unk_0xc: int = csfield(Int16ul)
    sections_offset: int = csfield(Int16ul)

