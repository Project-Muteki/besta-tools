from typing import BinaryIO


def simple_checksum(input_file: BinaryIO, size: int | None = None) -> int:
    buf = bytearray(1024)
    buf_mv = memoryview(buf)
    checksum = 0
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
