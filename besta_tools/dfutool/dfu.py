from __future__ import annotations

# Some resource on how to interface with USB mass storage devices without dedicated OS support:
# https://www.downtowndougbrown.com/2018/12/usb-mass-storage-with-embedded-devices-tips-and-quirks/

from array import array
from contextlib import AbstractContextManager
from errno import EIO
from typing import TYPE_CHECKING, Final, override
from io import SEEK_CUR, SEEK_END, SEEK_SET, BufferedRandom, BufferedReader, BufferedWriter, RawIOBase
from os import strerror
from random import randrange
import weakref

from usb import RECIP_INTERFACE
from usb.core import Device, Endpoint, Interface, USBError
from usb.util import CTRL_IN, ENDPOINT_IN, ENDPOINT_OUT, endpoint_direction, find_descriptor
from usb.legacy import CLASS_MASS_STORAGE, TYPE_CLASS

from besta_tools.dfutool.formats import CBW, CSW, BestaDfuCommand, BestaDfuConfigPacket, BestaDfuSbcOpcode, CSWError, CsBestaDfuConfigPacket, CsCBW, CsCSW, ReadCapacity10Response

from .usbms_const import SCSI_CMD_READ10, SCSI_CMD_READ_CAPACITY10, SCSI_CMD_TEST_UNIT_READY, SCSI_CMD_WRITE10, USB_INTERFACE_PROTOCOL_BBB, USB_INTERFACE_SUBCLASS_SCSI, USBMS_REQ_BBB_GET_MAX_LUN

if TYPE_CHECKING:
    from _typeshed import MaybeNone, ReadableBuffer, WriteableBuffer
    from types import TracebackType


# Maximum bulk transfer size. Currently only used for SCSI data transfers.
# 1MiB should be reasonable for all backends, but we need to test this.
MAX_BULK_XFER_SIZE: Final[int] = 1 * 1024 * 1024


class BestaNACK(RuntimeError):
    pass


# TODO: currently the device and/or the buffered I/O handle must be closed
# before the program exits (which, any well-written program should do anyway),
# or the BufferedRandom wrapper will attempt to flush the write buffer by
# accessing the device when it's already finalized (use-after-free).
# We might need to hook into the Device class so that it can be aware of the
# lifecycle of DfuDevice and its children.


class DfuDevice(AbstractContextManager):  # pyright: ignore[reportMissingTypeArgument], we're using it as an ABC
    dev: Device
    intf: Interface
    in_ep: Endpoint
    out_ep: Endpoint
    lun: int
    _lun_instances: list[Lun]

    _max_lun: int
    _capacity: ReadCapacity10Response

    _restore_driver: bool
    _closed: bool

    def __init__(self, dev: Device):
        self._restore_driver = False
        self._closed = False
        self.dev = dev
        self._lun_instances = []

        intf: Interface | None = None
        for cfg in dev:
            intf = find_descriptor(
                cfg,
                bInterfaceClass=CLASS_MASS_STORAGE,
                bInterfaceSubClass=USB_INTERFACE_SUBCLASS_SCSI,
                bInterfaceProtocol=USB_INTERFACE_PROTOCOL_BBB,
            )
            if intf is None:
                continue
            if self.dev.is_kernel_driver_active(intf.bInterfaceNumber):
                self.dev.detach_kernel_driver(intf.bInterfaceNumber)
                self._restore_driver = True
            self.dev.set_configuration(cfg.bConfigurationValue)
            break

        if intf is None:
            raise TypeError(f'Device {dev.address} does not seem to have a SCSI interface.')
        self.intf = intf

        in_ep = find_descriptor(self.intf, custom_match=lambda ep: endpoint_direction(ep.bEndpointAddress) == ENDPOINT_IN)
        out_ep = find_descriptor(self.intf, custom_match=lambda ep: endpoint_direction(ep.bEndpointAddress) == ENDPOINT_OUT)

        if in_ep is None or out_ep is None:
            raise TypeError(f'Device {dev.address} does not properly declare required endpoints.')

        self.in_ep, self.out_ep = in_ep, out_ep

        # GET_MAX_LUN is required, or the device refuses to talk to us.
        result = self.dev.ctrl_transfer(
            CTRL_IN | TYPE_CLASS | RECIP_INTERFACE,
            USBMS_REQ_BBB_GET_MAX_LUN,
            data_or_wLength=1,
        )
        assert isinstance(result, array)
        self._max_lun = result[0]

    @override
    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None, /) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return

        for i in self._lun_instances:
            i.close()
        self._lun_instances.clear()
        if self._restore_driver:
            self.dev.attach_kernel_driver(self.intf.bInterfaceNumber)
        del self.dev, self.intf, self.in_ep, self.out_ep

        self._closed = True

    def flush_all_lun(self) -> None:
        for i in self._lun_instances:
            i.flush_all_io()

    def get_lun(self, lun: int) -> Lun:
        i = Lun(self, lun)
        self._lun_instances.append(i)
        return i


class Lun(AbstractContextManager):  # pyright: ignore[reportMissingTypeArgument], we're using it as an ABC
    dev: DfuDevice
    lun: int
    _capacity: ReadCapacity10Response
    _io_instances: list[DfuIo]
    _bio_instances: list[BufferedReader | BufferedWriter | BufferedRandom]

    @property
    def capacity(self) -> ReadCapacity10Response:
        return self._capacity

    def __init__(self, dev: DfuDevice, lun: int) -> None:
        self.lun = lun
        self.dev = weakref.proxy(dev)
        self._io_instances = []
        self._bio_instances = []

        ready = False
        for _ in range(3):
            try:
                ret = self.scsi_test_unit_ready()
                if ret.bCSWStatus == 0:
                    ready = True
                    break
            except USBError:
                continue

        if not ready:
            raise RuntimeError('SCSI device not ready.')

        _, self._capacity = self.scsi_read_capacity10()

    def __del__(self) -> None:
        self.close()

    @override
    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None, /) -> None:
        self.close()

    def close(self) -> None:
        for i in self._bio_instances:
            i.close()
        self._bio_instances.clear()
        for ii in self._io_instances:
            ii.close()
        self._io_instances.clear()

    def flush_all_io(self) -> None:
        for i in self._bio_instances:
            i.flush()

    def get_io(self) -> DfuIo:
        i = DfuIo(self)
        self._io_instances.append(i)
        return i

    def get_buffered_io(self) -> BufferedRandom:
        i = BufferedRandom(DfuIo(self))
        self._bio_instances.append(i)
        return i

    def get_buffered_reader(self) -> BufferedReader:
        i = BufferedReader(DfuIo(self))
        self._bio_instances.append(i)  # pyright: ignore[reportArgumentType], mypy doesn't like it with generics
        return i  # pyright: ignore[reportReturnType]

    def get_buffered_writer(self) -> BufferedWriter:
        i = BufferedWriter(DfuIo(self))
        self._bio_instances.append(i)  # pyright: ignore[reportArgumentType], mypy doesn't like it with generics
        return i  # pyright: ignore[reportReturnType]

    def scsi_raw_write(self, cmd: bytes | bytearray, data: bytes | None = None) -> CSW:
        '''
        Send a write SCSI command and optionally send extra data.
        '''
        tag = randrange(0, 0x100000000)
        cbw = CBW(
            dCBWTag=tag,
            dCBWDataTransferLength=len(data) if data is not None else 0,
            bmCBWFlags=0x00,
            bCBWLUN=self.lun,
            CBWCB=cmd,
        )
        packet = CsCBW.build(cbw)
        self.dev.out_ep.write(packet)
        if data is not None:
            self.dev.out_ep.write(data)
        response = self.dev.in_ep.read(CsCSW.sizeof())
        csw = CsCSW.parse(response.tobytes())
        csw.dCSWTag ^= tag  # If tags are the same, returned dCSWTag should be a 0.
        return csw

    def scsi_raw_read(self, cmd: bytes | bytearray, length: int = 0) -> tuple[CSW, bytes]:
        '''
        Send a read SCSI command and optionally request data.
        '''
        tag = randrange(0, 0x100000000)
        cbw = CBW(
            dCBWTag=tag,
            dCBWDataTransferLength=length,
            bmCBWFlags=0x80,
            bCBWLUN=self.lun,
            CBWCB=cmd,
        )
        packet = CsCBW.build(cbw)
        self.dev.out_ep.write(packet)
        data = self.dev.in_ep.read(length).tobytes() if length > 0 else b''
        response = self.dev.in_ep.read(CsCSW.sizeof())
        csw = CsCSW.parse(response.tobytes())
        csw.dCSWTag ^= tag  # If tags are the same, returned dCSWTag should be a 0.
        return csw, data

    def scsi_raw_read_into(self, cmd: bytes | bytearray, buf: array[int] | None = None) -> tuple[CSW, int]:
        '''
        Send a read SCSI command and optionally request data.
        '''
        tag = randrange(0, 0x100000000)
        cbw = CBW(
            dCBWTag=tag,
            dCBWDataTransferLength=len(buf) if buf is not None else 0,
            bmCBWFlags=0x80,
            bCBWLUN=self.lun,
            CBWCB=cmd,
        )
        packet = CsCBW.build(cbw)
        self.dev.out_ep.write(packet)
        read_size = 0
        if buf is not None:
            read_size = self.dev.in_ep.read(buf)
        response = self.dev.in_ep.read(CsCSW.sizeof())
        csw = CsCSW.parse(response.tobytes())
        csw.dCSWTag ^= tag  # If tags are the same, returned dCSWTag should be a 0.
        return csw, read_size

    def scsi_besta_set_config(self, cmd: BestaDfuCommand, param: int, data: bytes | None = None) -> CSW:
        req = BestaDfuConfigPacket(
            command=cmd,
            parameter=param
        )
        scsi_cmd = bytearray(16)
        scsi_cmd[0] = BestaDfuSbcOpcode.SET_CONFIG
        if data is not None:
            payload = bytearray(256)
            payload[:len(data)] = data
            req.payload = payload
        return self.scsi_raw_write(scsi_cmd, CsBestaDfuConfigPacket.build(req))

    def scsi_besta_get_config(self) -> tuple[CSW, BestaDfuConfigPacket]:
        scsi_cmd = bytearray(16)
        scsi_cmd[0] = BestaDfuSbcOpcode.GET_CONFIG
        ret, res_data = self.scsi_raw_read(scsi_cmd, CsBestaDfuConfigPacket.sizeof())
        res = CsBestaDfuConfigPacket.parse(res_data)
        return ret, res

    def scsi_read10(self, lba: int, blks: int, flags: int = 0, group: int = 0, control: int = 0) -> tuple[CSW, bytes]:
        '''
        Issue a SCSI Read(10) command.
        '''
        scsi_cmd = bytearray(10)
        scsi_cmd[0] = SCSI_CMD_READ10
        scsi_cmd[1] = flags
        scsi_cmd[2:6] = lba.to_bytes(4, 'big')
        scsi_cmd[6] = group & 0b11111
        scsi_cmd[7:9] = blks.to_bytes(2, 'big')
        scsi_cmd[9] = control
        ret, res_data = self.scsi_raw_read(scsi_cmd, blks * self._capacity.sector_size)
        return ret, res_data

    def scsi_write10(self, lba: int, data: bytes, flags: int = 0, group: int = 0, control: int = 0) -> CSW:
        '''
        Issue a SCSI Write(10) command. Length of input data must be aligned to sector boundary.
        '''
        blks, leftover = divmod(len(data), self._capacity.sector_size)
        if leftover != 0:
            raise ValueError('Length of data does not align to sector boundary.')

        scsi_cmd = bytearray(10)
        scsi_cmd[0] = SCSI_CMD_WRITE10
        scsi_cmd[1] = flags
        scsi_cmd[2:6] = lba.to_bytes(4, 'big')
        scsi_cmd[6] = group & 0b11111
        scsi_cmd[7:9] = blks.to_bytes(2, 'big')
        scsi_cmd[9] = control
        ret = self.scsi_raw_write(scsi_cmd, data)
        return ret

    def scsi_read_capacity10(self, control: int = 0) -> tuple[CSW, ReadCapacity10Response]:
        '''
        Issue a SCSI Read Capacity(10) command.

        Windows seems to call this every time before doing Read(10) and Write(10).
        '''
        scsi_cmd = bytearray(10)
        scsi_cmd[0] = SCSI_CMD_READ_CAPACITY10
        scsi_cmd[9] = control
        ret, res_data = self.scsi_raw_read(scsi_cmd, 8)
        return ret, ReadCapacity10Response.from_bytes(res_data)

    def scsi_test_unit_ready(self, control: int = 0) -> CSW:
        scsi_cmd = bytearray(6)
        scsi_cmd[0] = SCSI_CMD_TEST_UNIT_READY
        scsi_cmd[5] = control
        ret = self.scsi_raw_write(scsi_cmd)
        return ret

    @staticmethod
    def besta_check_ack(packet: BestaDfuConfigPacket, cmd: BestaDfuCommand, param: int | None = None) -> bool:
        return packet.command == cmd | BestaDfuCommand.ACK and (param is None or packet.parameter == param | BestaDfuCommand.ACK)

    def ping(self) -> bool:
        ret = self.scsi_besta_set_config(BestaDfuCommand.CMD_PING, BestaDfuCommand.CMD_PING_ARG)
        if ret.bCSWStatus != 0:
            print('SET_CONFIG bCSWStatus error', ret)
            return False

        ret, res = self.scsi_besta_get_config()
        if ret.bCSWStatus != 0:
            print('GET_CONFIG bCSWStatus error', ret)
            return False

        if self.besta_check_ack(res, BestaDfuCommand.CMD_PING, BestaDfuCommand.CMD_PING_ARG):
            return True
        else:
            print('NACK', res)
            return False

    def set_progress(self, value: int) -> None:
        ret = self.scsi_besta_set_config(BestaDfuCommand.CMD_SET_PROGRESS, value)
        if ret.bCSWStatus != 0:
            raise CSWError(ret.bCSWStatus)

        ret, res = self.scsi_besta_get_config()
        if ret.bCSWStatus != 0:
            raise CSWError(ret.bCSWStatus)

        if not self.besta_check_ack(res, BestaDfuCommand.CMD_SET_PROGRESS):
            raise BestaNACK('Device NACKed the DFU request.')

    def reboot(self) -> None:
        # Signal the parent to flush all children, including ourselves
        self.dev.flush_all_lun()
        ret = self.scsi_besta_set_config(BestaDfuCommand.CMD_REBOOT, 0)
        if ret.bCSWStatus != 0:
            raise CSWError(ret.bCSWStatus)
        self.dev.close()


class DfuIo(RawIOBase):
    '''
    RawIO wrapper for a DFU LUN object.

    The I/O will generally stop at the LBA size boundary of the LUN. That is,
    it can be one of the following:
    - If the amount of requested data perfectly aligns with LBA
      (_boffset == 0, size aligns with LBA size), just read and return.
    - If the amount of requested data is less than a LBA (_boffset + size is
      less than a LBA), read and truncate the data, update _boffset
      accordingly.
    - If the amount of requested data is more than or equal to a LBA
      (_boffset + size is more than or equal to a LBA), read data only up
      to the closest LBA (e.g. if _boffset is 3, _lbasize is 512 and size
      is 8192, only return the last 8192 - 3 = 8189 bytes read).
    '''

    _lun: Lun
    _lbasize: int

    _lba: int
    _boffset: int

    def __init__(self, lun: Lun):
        self._lun = weakref.proxy(lun)
        self._lba = 0
        self._boffset = 0
        self._lbasize = lun.capacity.sector_size

    def _plan_io(self, size: int) -> tuple[int, int, int, int]:
        '''
        Plan I/O operation, taking the current LBA byte offset into account.

        Returns the number of blocks to read/write and the right buffer trim
        offset.
        '''
        nlba = self._lun.capacity.nlba
        boffset = self._boffset
        lbasize = self._lbasize
        lba = self._lba

        # Limit size to be within the boundary of remaining data.
        total_size = nlba * lbasize
        current_offset = lba * lbasize + boffset
        size = min(size, max(0, total_size - current_offset))

        new_lba, new_boffset = divmod(current_offset + size, lbasize)

        if lba == new_lba:
            # Same block, truncate
            return 1, new_boffset, new_lba, new_boffset
        elif new_lba - lba == 1 and new_boffset == 0:
            # Same block, do not truncate the right side
            return 1, lbasize if boffset != 0 else 0, new_lba, new_boffset
        else:
            # Cut-off the partial block I/O within the multi-block I/O
            return new_lba - lba, 0, new_lba, 0

    @override
    def read(self, size: int = -1, /) -> bytes | MaybeNone:
        '''
        Read bytes up to size.
        '''
        if size < 0 or size > MAX_BULK_XFER_SIZE:
            size = MAX_BULK_XFER_SIZE
        elif size == 0:
            return b''

        nlba = self._lun.capacity.nlba
        lba = self._lba
        if nlba <= lba:
            return b''

        ltrim = self._boffset
        blks, rtrim, new_lba, new_boffset = self._plan_io(size)

        res, data = self._lun.scsi_read10(lba, blks)
        if res.bCSWStatus != 0:
            raise IOError(EIO, strerror(EIO))

        if ltrim != 0 or rtrim != 0:
            data = data[ltrim:rtrim] if rtrim != 0 else data[ltrim:]
        self._lba, self._boffset = new_lba, new_boffset

        return data

    @override
    def readinto(self, buffer: WriteableBuffer, /) -> int | MaybeNone:
        # TODO optimize
        mv = memoryview(buffer)
        buf = self.read(len(mv))
        mv[:len(buf)] = buf

        return len(buf)

    @override
    def write(self, b: ReadableBuffer, /) -> int | MaybeNone:
        mv = memoryview(b)
        size = len(mv)

        if size > MAX_BULK_XFER_SIZE:
            size = MAX_BULK_XFER_SIZE
        elif size == 0:
            return 0

        nlba = self._lun.capacity.nlba
        lba = self._lba
        if nlba <= lba:
            return 0

        lpad = self._boffset
        blks, rpad, new_lba, new_boffset = self._plan_io(size)
        print(blks, rpad, new_lba, new_boffset)

        written: int
        wbuf: memoryview | bytearray
        if lpad == 0 and rpad == 0:
            written = blks * self._lbasize
            wbuf = mv[:written]
            #print('whole lba', lba, 'data', mv[:written].hex())
        elif rpad != 0:
            res, data = self._lun.scsi_read10(lba, 1)
            if res.bCSWStatus != 0:
                raise IOError(EIO, strerror(EIO))
            data_a = bytearray(data)
            data_a[lpad:rpad] = mv[:rpad - lpad]
            assert len(data_a) % self._lbasize == 0
            wbuf = data_a
            #print('single lba', lba, 'data', data_a.hex())
            written = rpad - lpad
        else:
            res, data = self._lun.scsi_read10(lba, 1)
            if res.bCSWStatus != 0:
                raise IOError(EIO, strerror(EIO))
            data_a = bytearray()
            written = blks * self._lbasize - lpad
            data_a.extend(data[:lpad])
            data_a.extend(mv[:written])
            assert len(data_a) % self._lbasize == 0
            wbuf = data_a
            #print('multiple lba', lba, 'data', data_a.hex())

        res = self._lun.scsi_write10(lba, bytes(wbuf))
        if res.bCSWStatus != 0:
           raise IOError(EIO, strerror(EIO))

        self._lba, self._boffset = new_lba, new_boffset
        return written

    @override
    def seek(self, offset: int, whence: int = SEEK_SET, /) -> int:
        blksize = self._lbasize

        if whence == SEEK_SET:
            self._lba, self._boffset = divmod(offset, blksize)
        elif whence == SEEK_CUR:
            old_off = self.tell()
            self._lba, self._boffset = divmod(old_off + offset, blksize)
        elif whence == SEEK_END:
            self._lba, self._boffset = divmod(blksize * self._lun.capacity.nlba + offset, blksize)

        return self.tell()

    @override
    def tell(self) -> int:
        return self._lba * self._lbasize + self._boffset

    @override
    def readable(self) -> bool:
        return True

    @override
    def writable(self) -> bool:
        return True

    @override
    def seekable(self) -> bool:
        return True
