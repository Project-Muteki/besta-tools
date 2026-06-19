from click._termui_impl import ProgressBar
from typing import AnyStr, TYPE_CHECKING, Callable
from dataclasses import dataclass
from itertools import islice
from io import BufferedReader, BytesIO, SEEK_END, SEEK_SET
import shutil
import os

import click
from typing_extensions import Never

if TYPE_CHECKING:
    from _typeshed import SupportsRead, SupportsWrite


COPY_BUFSIZE = 1024 * 1024 if os.name == 'nt' else 64 * 1024


@dataclass
class Fragment:
    offset: int
    size: int
    data: bytes | bytearray | memoryview | None = None

    def set_data(self, data: bytes | bytearray | memoryview):
        if self.size != len(data):
            raise ValueError('Size mismatch.')
        self.data = data


class BinaryBuilder:
    _fragments: list[Fragment]
    _last_offset: int

    def __init__(self, base: int = 0):
        self._fragments = []
        self._last_offset = base

    def append(self, size: int) -> Fragment:
        result = Fragment(self._last_offset, size, None)
        self._fragments.append(result)
        self._last_offset += size
        return result

    def concat(self) -> bytes:
        result = BytesIO()
        
        for fragment in self._fragments:
            if fragment.data is not None:
                result.write(fragment.data)
        return result.getvalue()

    def sizeof(self):
        return self._last_offset


class Checksum:
    _init: int
    _checksum: list[int]
    _blksize: int | None
    _blkremaining: int | None
    _offset: int

    def __init__(self, blksize: int | None = None, /, init: int = 0) -> None:
        if blksize is not None and blksize <= 0:
            raise ValueError('Block size must be greater than 0.')

        self._init = init
        self._checksum = [init]
        self._blksize = blksize
        self._blkremaining = blksize
        self._offset = 0

    def update(self, data: bytes | bytearray | memoryview) -> None:
        if self._blkremaining is None:
            self._checksum[-1] += sum(data)
            return

        assert self._blksize is not None

        data_mv = memoryview(data)
        while len(data_mv) != 0:
            bytes_to_process = self._blkremaining
            if len(data_mv) >= bytes_to_process:
                self._checksum[-1] += sum(data_mv[:bytes_to_process])
                self._blkremaining = self._blksize
                self._checksum.append(self._init)
            else:
                self._checksum[-1] += sum(data_mv)
                self._blkremaining -= len(data_mv)
            data_mv = data_mv[bytes_to_process:]

        self._offset += len(data)

    def digest(self) -> list[int]:
        gen = (c & 0xffff for c in self._checksum)
        if self._blksize is not None and self._blkremaining == self._blksize:
            return list(islice(gen, len(self._checksum) - 1))
        return list(gen)

    def bytes_processed(self) -> int:
        return self._offset

    def write(self, data: bytes | bytearray | memoryview) -> None:
        self.update(data)
    
    def tell(self) -> int:
        return self.bytes_processed()


def simple_checksum(input_file: BufferedReader | BytesIO, size: int | None = None) -> int:
    buf = bytearray(1024)
    buf_mv = memoryview(buf)
    checksum = Checksum()
    bytes_left: int

    if size is None:
        old_pos = input_file.tell()
        bytes_left = input_file.seek(0, SEEK_END) - old_pos
        input_file.seek(old_pos, SEEK_SET)
    else:
        bytes_left = size

    while True:
        if bytes_left == 0:
            break

        actual = input_file.readinto(buf)  # readinto does exist in BytesIO

        if actual == 0:
            break
        elif actual > bytes_left:
            actual = bytes_left

        checksum.update(buf_mv[:actual])
        bytes_left -= actual

    d = checksum.digest()
    if len(d) == 0:
        return 0
    return d[0]


def copyfileobjex(
    fsrc: 'SupportsRead[AnyStr]',
    fdst: 'SupportsWrite[AnyStr]',
    length: int = COPY_BUFSIZE,
    limit: int | None = None
) -> None:
    if limit is None:
        shutil.copyfileobj(fsrc, fdst, length)
        return

    w = fdst.write
    r = fsrc.read

    while limit > 0:
        bytes_to_read = min(length, limit)
        data = r(bytes_to_read)
        if len(data) == 0:
            break
        w(data)
        limit -= bytes_to_read


def copyfileobjex_progress(
    fsrc: 'SupportsRead[AnyStr]',
    fdst: 'SupportsWrite[AnyStr]',
    limit: int,
    length: int = COPY_BUFSIZE,
    progress_callback: Callable[[int], None] | None = None
) -> None:
    w = fdst.write
    r = fsrc.read

    while limit > 0:
        bytes_to_read = min(length, limit)
        data = r(bytes_to_read)
        if len(data) == 0:
            break
        w(data)
        limit -= bytes_to_read
        if progress_callback is not None:
            progress_callback(bytes_to_read)


def is_strictly_nul_terminated(buf: bytes | bytearray | memoryview) -> bool:
    phase = 0
    segment_counter = 0
    for c in reversed(buf):
        if c == 0 and phase != -1:
            phase = -1
            segment_counter += 1
        elif c != 0 and phase != 1:
            phase = 1
            segment_counter += 1
    return buf[-1] == 0 and segment_counter == 2


def align(pos: int, blksize: int, greedy: bool = False) -> int:
    return (pos // blksize * blksize) + (blksize if greedy or pos % blksize != 0 else 0)


def generate_padding(length: int, blksize: int, greedy: bool = False, pad_byte: int | None = None) -> bytes:
    pad_byte_b = bytearray(1)
    if pad_byte is not None:
        pad_byte_b[0] = pad_byte
    else:
        pad_byte_b[0] = 0
    return bytes(pad_byte_b) * (align(length, blksize, greedy=greedy) - length)


def div_round_up(a: float, b: float) -> int:
    return int(-(-a // b))
