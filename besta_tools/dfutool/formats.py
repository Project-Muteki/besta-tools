from typing import cast, TYPE_CHECKING
if TYPE_CHECKING:
    from construct import Context, Const, Construct

import dataclasses
from enum import IntEnum, IntFlag

from construct import (
    Bytes,
    Default,
    Int8ul,
    Int32ul,
    this
)
from construct_typed import DataclassMixin, DataclassStruct, FlagsEnumBase, TFlagsEnum, csfield

from .usbms_const import *


class BestaDfuSbcOpcode(IntEnum):
    SET_CONFIG = 0x88
    GET_CONFIG = 0x89


class BestaDfuCommand(FlagsEnumBase):
    CMD_PING_ARG = 0xbead
    CMD_ERASE_AND_SCAN = 0xbec2
    CMD_PROBE_REGION = 0xbec5
    CMD_UPLOAD_BOOTLOADER = 0xbec6
    CMD_COMMIT_BOOTLOADER = 0xbec7
    CMD_PING = 0xbecd
    CMD_SET_PROGRESS = 0xbedc
    ACK = 0x80000000


CsBestaDfuCommand = TFlagsEnum(Int32ul, BestaDfuCommand)


@dataclasses.dataclass
class CBW(DataclassMixin):
    dCBWSignature: int = csfield(Const(USBMS_CBW_MAGIC, Int32ul))
    dCBWTag: int = csfield(Int32ul)
    dCBWDataTransferLength: int = csfield(Int32ul)
    bmCBWFlags: int = csfield(Int8ul)
    bCBWLUN: int = csfield(Int8ul)
    bCBWCBLength: int = csfield(Int8ul)


@dataclasses.dataclass
class BestaDfuConfigPacket(DataclassMixin):
    command: int = csfield(CsBestaDfuCommand)
    parameter: int = csfield(Int32ul)
    payload: bytes = csfield(Default(Bytes(256), b'\x00' * 256))


CsBestaDfuConfigPacket = DataclassStruct(BestaDfuConfigPacket)
