from typing import BinaryIO
from dataclasses import dataclass
import io


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
        result = io.BytesIO()
        for fragment in self._fragments:
            result.write(fragment.data)
        return result.getvalue()

    def sizeof(self):
        return self._last_offset


def simple_checksum(input_file: BinaryIO, size: int | None = None) -> int:
    buf = bytearray(1024)
    buf_mv = memoryview(buf)
    checksum = 0

    if size is None:
        old_pos = input_file.tell()
        bytes_left = input_file.seek(0, io.SEEK_END) - old_pos
        input_file.seek(old_pos, io.SEEK_SET)
    else:
        bytes_left = size

    while True:
        if bytes_left == 0:
            break

        actual = input_file.readinto(buf)

        if actual == 0:
            break
        elif actual > bytes_left:
            actual = bytes_left

        checksum += sum(buf_mv[:actual])
        if bytes_left is not None:
            bytes_left -= actual

    return checksum & 0xffff
