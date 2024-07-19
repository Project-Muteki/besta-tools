from typing import BinaryIO, Self, cast, TYPE_CHECKING
if TYPE_CHECKING:
    from construct import Context

import dataclasses
from pathlib import Path

from construct import (
    Array,
    Byte,
    Bytes,
    Computed,
    Const,
    Check,
    IfThenElse,
    Int16ul,
    Int32ul,
    Int64ul,
    PaddedString,
    Padding,
    Rebuild,
    this,
    len_
)
from construct_typed import DataclassMixin, DataclassStruct, EnumBase, TEnum, csfield

from ..common.formats import CsChecksumValue, ChecksumValue
from ..common.utils import simple_checksum


IMAGE_INDEX_V2_MAGIC = b'\xaa\x55\xaa\x55'


def guess_block_size_image_v2(f: BinaryIO, search_limit: int = 0x100000, step_size: int = 16) -> int:
    for offset in range(0, search_limit, step_size):
        f.seek(offset)
        if f.read(step_size)[:4] == IMAGE_INDEX_V2_MAGIC:
            return offset
    raise RuntimeError('Cannot determine block size.')


def _inv_u16_per_byte(ctx: 'Context') -> int:
    value = cast(int, ctx.checksum)
    lo = value & 0xff
    hi = (value >> 8) & 0xff
    return (((0x100 - hi) & 0xff) << 8) | ((0x100 - lo) & 0xff)


@dataclasses.dataclass
class ImageMetadataV2(DataclassMixin):
    image_name: str = csfield(PaddedString(16, 'ascii'))
    image_version: str = csfield(PaddedString(16, 'ascii'))
    os_version: str = csfield(PaddedString(16, 'ascii'))
    content_size: int = csfield(Int64ul)
    data_size: int = csfield(Int64ul)
    checksum_block_size: int = csfield(Int32ul)
    unk_0x44: int = csfield(Int32ul)
    _padding_0x48: int = csfield(Padding(24))
    has_checksum: bool = csfield(Computed(this.checksum_block_size != 0))
    checksums: list[ChecksumValue] = csfield(IfThenElse(
        this.has_checksum,
        Array(this.data_size // this.checksum_block_size, CsChecksumValue),
        Array(0, CsChecksumValue),
    ))


CsImageMetadataV2 = DataclassStruct(ImageMetadataV2)


@dataclasses.dataclass
class ImageIndexEntryV2(DataclassMixin):
    offset: int = csfield(Int64ul)
    size: int = csfield(Int64ul)
    _integrity: None = csfield(Check(this.offset != (1 << 64) - 1 and this.size != (1 << 64) - 1))


CsImageIndexEntryV2 = DataclassStruct(ImageIndexEntryV2)


@dataclasses.dataclass
class ImageIndexV2(DataclassMixin):
    magic: bytes = csfield(Const(IMAGE_INDEX_V2_MAGIC))
    header_size: int = csfield(Const(0x40, Int32ul))
    format_version: int = csfield(Const(0x20090828, Int32ul))
    nentries: int = csfield(Rebuild(Int32ul, len_(this.entries)))
    _padding_0x10: None = csfield(Padding(0x30))
    entries: list[ImageIndexEntryV2] = csfield(Array(this.nentries, CsImageIndexEntryV2))


CsImageIndexV2 = DataclassStruct(ImageIndexV2)


@dataclasses.dataclass
class ImageFileV2:
    path: Path
    metadata: ImageMetadataV2
    index: ImageIndexV2

    @classmethod
    def load(cls, image_path: str | Path) -> Self:
        image_path = Path(image_path)
        with image_path.open('rb') as f:
            block1_offset = guess_block_size_image_v2(f)
            f.seek(0)
            metadata = CsImageMetadataV2.parse_stream(f)
            f.seek(block1_offset)
            index = CsImageIndexV2.parse_stream(f)
        return cls(image_path, metadata, index)

    def verify(self) -> list[bool]:
        results: list[bool] = []
        with self.path.open('rb') as f:
            for offset, checksum in zip(
                    range(0, self.metadata.data_size, self.metadata.checksum_block_size),
                    self.metadata.checksums
            ):
                f.seek(offset)
                checksum_actual = simple_checksum(f, self.metadata.checksum_block_size)
                results.append(checksum_actual == checksum.checksum)
        return results
