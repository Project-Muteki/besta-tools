from dataclasses import dataclass
from enum import StrEnum
from io import SEEK_CUR, BufferedReader
from typing import Self

from besta_tools.common.utils import is_strictly_nul_terminated


IMAGE_TYPE_SYSTEM_DATA_MAGIC = 0x0001801d
IMAGE_INDEX_V2_MAGIC = b'\xaa\x55\xaa\x55'
IMAGE_INDEX_V1_MAGIC = IMAGE_TYPE_SYSTEM_DATA_MAGIC.to_bytes(4, 'little')


class ProbeError(RuntimeError):
    pass


class KernelArch(StrEnum):
    UNSET = ''
    ARMV5 = 'V5J'
    ARMV5_NUVOTON = 'W55'
    ARMV6 = 'V6K'

    @classmethod
    def from_bytes(cls, b: bytes) -> Self:
        try:
            s = b.decode('ascii').rstrip('\x00')
        except UnicodeDecodeError:
            return cls('')
        try:
            return cls(s)
        except ValueError:
            return cls('')


class SocType(StrEnum):
    UNSET = ''
    S3C2450 = '2450'
    STMP3738 = '3738'
    IMX233 = '3780'
    TCC8902 = '8902'
    N32926 = 'FA92'
    N3290X = 'FA93'

    @classmethod
    def from_bytes(cls, b: bytes) -> Self:
        try:
            s = b.decode('ascii').rstrip('\x00')
        except UnicodeDecodeError:
            return cls('')
        try:
            return cls(s)
        except ValueError:
            return cls('')


@dataclass
class ProbeResultKernel:
    header_format_version: int
    trailer_format_version: int
    trailer_offset: int
    arch: KernelArch
    soc: str


@dataclass
class ProbeResultData:
    header_format_version: int
    index_type: int
    block_size: int


def _test_format_version(f: BufferedReader, base_offset: int) -> int | None:
    f.seek(base_offset + 16)

    seq1 = f.read(16)
    seq2 = f.read(16)

    if len(seq1) < 16 or len(seq2) < 16:
        raise ProbeError('Header too small to be an image file.')

    if is_strictly_nul_terminated(seq1) and (is_strictly_nul_terminated(seq2) or not any(seq2)):
        return 2
    # seq2 will contain the first 2 checksum values so very likely they won't be NUL and will fail the test.
    elif is_strictly_nul_terminated(seq1[:12]) and not is_strictly_nul_terminated(seq2):
        return 1
    
    return None


def _test_kernel_format_version(
    f: BufferedReader,
    base_offset: int,
    search_limit: int,
    jump_limit: int,
    step_size: int,
) -> tuple[int, int] | None:
    f.seek(base_offset + 0x10)

    kernel_size_bytes = f.read(4)
    if len(kernel_size_bytes) < 4:
        raise ProbeError('Header too small to be a kernel image file.')
    kernel_size = int.from_bytes(kernel_size_bytes, 'little')
    if kernel_size > jump_limit:
        return None

    limit = min(kernel_size - 0x500, search_limit)

    if limit < step_size or limit % step_size != 0:
        return None
    
    for diff in range(0, limit, step_size):
        offset = base_offset + kernel_size - diff - 0x500
        trailer_version = _test_format_version(f, offset)
        if trailer_version is not None:
            return trailer_version, offset - base_offset

    return None


def probe_image(
    f: BufferedReader,
    search_limit: int = 0x100000,
    jump_limit: int = 0x1000000,
    step_size: int = 16,
    from_here: bool = False,
) -> ProbeResultKernel | ProbeResultData:
    header_format_version = None
    block_size = None
    index_type = None
    trailer_format_version = None
    trailer_offset = None
    arch = None
    soc = None

    base_offset = f.seek(0, SEEK_CUR) if from_here else 0

    header_format_version = _test_format_version(f, base_offset)

    if header_format_version is None:
        # Detect kernel image
        res = _test_kernel_format_version(f, base_offset, search_limit, jump_limit, step_size)
        if res is not None:
            trailer_format_version, trailer_offset = res
            f.seek(base_offset + 0x14)
            arch = KernelArch.from_bytes(f.read(4))
            soc = SocType.from_bytes(f.read(4))
            if arch == KernelArch.UNSET and soc == SocType.UNSET:
                header_format_version = 1
            else:
                header_format_version = 2
            return ProbeResultKernel(header_format_version, trailer_format_version, trailer_offset, arch, soc)
        else:
            raise ProbeError('Cannot determine format version.')

    for offset in range(0, search_limit, step_size):
        f.seek(base_offset + offset)
        marker = f.read(step_size)[:4]
        if marker == IMAGE_INDEX_V2_MAGIC:
            index_type = 2
            block_size = offset
        elif marker == IMAGE_INDEX_V1_MAGIC:
            index_type = 1
            block_size = offset

    if index_type is None:
        raise ProbeError('Cannot determine index type.')
    if block_size is None:
        raise ProbeError('Cannot determine block size.')
    
    return ProbeResultData(header_format_version, index_type, block_size)
