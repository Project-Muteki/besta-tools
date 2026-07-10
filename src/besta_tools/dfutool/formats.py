from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from logging import getLogger
from typing import NamedTuple, Self, override

from construct import (
    Bytes,
    Const,
    Default,
    Int8ul,
    Int32ul,
    Padded,
    Rebuild,
    len_,
    this,
)
from construct_typed import DataclassMixin, DataclassStruct, csfield

from ..common.tenum_patched import FlagsEnumBase, TFlagsEnum
from .usbms_const import *


logger = getLogger('besta_tools.dfutool.dfu')


class CSWError(RuntimeError):
    STATUS_MAP: dict[int, str] = {
        0: 'Command passed',
        1: 'Command failed',
        2: 'Phase error',
    }
    status: int
    residue: int
    tag_mismatch: bool

    def __init__(self, status: int, residue: int = 0, tag_mismatch: bool = False, *args: object) -> None:
        super().__init__(*args)
        self.status = status
        self.residue = residue
        self.tag_mismatch = tag_mismatch

    @override
    def __str__(self) -> str:
        residue_str = f' ({self.residue} bytes short)' if self.residue != 0 else ''
        tag_str = f' (tag mismatch)' if self.tag_mismatch else ''
        return f'[bCSWStatus={self.status}] {self.STATUS_MAP.get(self.status, '')}{residue_str}{tag_str}'


class BestaDfuSbcOpcode(IntEnum):
    SET_CONFIG = 0x88
    GET_CONFIG = 0x89


class BestaDfuCommand(FlagsEnumBase):
    CMD_PING_ARG = 0xbead
    CMD_REBOOT = 0xbec1
    CMD_ERASE_AND_SCAN = 0xbec2
    CMD_PROBE_REGION = 0xbec5
    CMD_UPLOAD_BOOTLOADER = 0xbec6
    CMD_COMMIT_BOOTLOADER = 0xbec7
    CMD_PING = 0xbecd
    CMD_SET_PROGRESS = 0xbedc
    ACK = 0x80000000


CsBestaDfuCommand = TFlagsEnum(Int32ul, BestaDfuCommand)


@dataclass
class CBW(DataclassMixin):
    dCBWSignature: int = csfield(Const(USBMS_CBW_MAGIC, Int32ul))
    dCBWTag: int = csfield(Int32ul)
    dCBWDataTransferLength: int = csfield(Int32ul)
    bmCBWFlags: int = csfield(Int8ul)
    bCBWLUN: int = csfield(Int8ul)
    bCBWCBLength: int = csfield(Rebuild(Int8ul, len_(this.CBWCB)))
    CBWCB: bytes | bytearray = csfield(Padded(16, Bytes(this.bCBWCBLength)))


CsCBW = DataclassStruct(CBW)


@dataclass
class CSW(DataclassMixin):
    dCSWSignature: int = csfield(Const(USBMS_CSW_MAGIC, Int32ul))
    dCSWTag: int = csfield(Int32ul)
    dCSWDataResidue: int = csfield(Int32ul)
    bCSWStatus: int = csfield(Int8ul)

    def check(self, tag: int = 0) -> None:
        # dfu.py routines will usually xor the tag with the expected one so
        # checking with 0 will work in most cases.
        tag_mismatch = False
        if self.dCSWTag != tag:
            tag_mismatch = True

        if tag_mismatch or self.dCSWDataResidue != 0 or self.bCSWStatus != 0:
            raise CSWError(self.bCSWStatus, self.dCSWDataResidue, tag_mismatch)

    def check_bool(self, tag: int = 0) -> bool:
        try:
            self.check(tag)
        except CSWError as e:
            logger.error('%s', str(e))
            return False
        return True


CsCSW = DataclassStruct(CSW)


@dataclass
class BestaDfuConfigPacket(DataclassMixin):
    command: int = csfield(CsBestaDfuCommand)
    parameter: int = csfield(Int32ul)
    payload: bytes | bytearray = csfield(Default(Bytes(256), b'\x00' * 256))


CsBestaDfuConfigPacket = DataclassStruct(BestaDfuConfigPacket)


class ReadCapacity10Response(NamedTuple):
    max_lba: int
    sector_size: int

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        if len(data) != 8:
            raise ValueError('Data length must be 8.')

        mv = memoryview(data)
        return cls(
            int.from_bytes(mv[0:4], 'big'),
            int.from_bytes(mv[4:8], 'big'),
        )

    @property
    def size_bytes(self) -> int:
        return (self.max_lba + 1) * self.sector_size
