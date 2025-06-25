from typing import BinaryIO, Self, cast, TYPE_CHECKING
if TYPE_CHECKING:
    from construct import Context

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from construct import (
    Array,
    Computed,
    Const,
    Check,
    IfThenElse,
    Int32ul,
    Int64ul,
    PaddedString,
    Padding,
    Rebuild,
    this,
    len_
)
from construct_typed import DataclassMixin, DataclassStruct, csfield
from marshmallow_dataclass import dataclass as mm_dataclass
from marshmallow_dataclass import class_schema as mm_class_schema

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


@dataclass
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


@dataclass
class ImageIndexEntryV2(DataclassMixin):
    offset: int = csfield(Int64ul)
    size: int = csfield(Int64ul)
    _integrity: None = csfield(Check(this.offset != (1 << 64) - 1 and this.size != (1 << 64) - 1))


CsImageIndexEntryV2 = DataclassStruct(ImageIndexEntryV2)


IMAGE_INDEX_V2_VERSIONS: set[int] = {
    0x20090828,
    0x20081202,
}


@dataclass
class ImageIndexV2(DataclassMixin):
    magic: bytes = csfield(Const(IMAGE_INDEX_V2_MAGIC))
    header_size: int = csfield(Const(0x40, Int32ul))
    format_version: int = csfield(Int32ul)
    _integrity_supported_format_version: None = csfield(Check(
        lambda ctx: ctx.format_version in IMAGE_INDEX_V2_VERSIONS
    ))
    nentries: int = csfield(Rebuild(Int32ul, len_(this.entries)))
    _padding_0x10: None = csfield(Padding(0x30))
    entries: list[ImageIndexEntryV2] = csfield(Array(this.nentries, CsImageIndexEntryV2))


CsImageIndexV2 = DataclassStruct(ImageIndexV2)


@mm_dataclass
class ImageManifestSection:
    path: str
    align: int = field(default=1, metadata={'required': False})


@mm_dataclass
class ImageManifest:
    header_format_version: int
    index_format_version: int
    name: str
    version_string: str
    block_size: int
    checksum_block_size: int
    sections: list[ImageManifestSection]


MmImageManifest = mm_class_schema(ImageManifest)


@dataclass
class ImageFileV2:
    path: Path
    metadata: ImageMetadataV2 | None = field(default=None)
    index: ImageIndexV2 | None = field(default=None)
    manifest: ImageManifest | None = field(default=None)

    def __post_init__(self):
        if self.manifest is None:
            self._build_manifest()

    def _build_manifest(self):
        with self.path.open('rb') as f:
            guessed_block_size = guess_block_size_image_v2(f)

        sections: list[ImageManifestSection] = [
            ImageManifestSection(f'sections/{i:08x}.bin') for i in range(self.index.nentries)
        ]

        self.manifest = ImageManifest(
            2,
            self.index.format_version,
            self.metadata.image_name,
            self.metadata.image_version,
            guessed_block_size,
            self.metadata.checksum_block_size,
            sections
        )

    @classmethod
    def load(cls, image_path: str | Path) -> Self:
        image_path = Path(image_path)
        with image_path.open('rb') as f:
            block1_offset = guess_block_size_image_v2(f)
            f.seek(0)
            metadata = CsImageMetadataV2.parse_stream(f)
            f.seek(block1_offset)
            index = CsImageIndexV2.parse_stream(f)

        return cls(image_path, metadata=metadata, index=index)

    def build(self, output: str | Path) -> None:
        block0_init = bytearray(self.manifest.block_size)
        metadata = CsImageMetadataV2.build(self.metadata)
        block0_init[:len(metadata)] = metadata
        index = CsImageIndexV2.build(self.index)
        # TODO

    def extract(self, output: str | Path) -> None:
        output = Path(output)
        output.mkdir(exist_ok=True)
        with (output / 'manifest.yaml').open('w') as manifest_file:
            yaml.safe_dump(MmImageManifest().dump(self.manifest), manifest_file, sort_keys=False)
        with self.path.open('rb') as image_file:
            for section, entry in zip(self.manifest.sections, self.index.entries):
                section_file_path = output / section.path
                section_file_path.parent.mkdir(exist_ok=True)
                with section_file_path.open('wb') as section_file:
                    image_file.seek(entry.offset)
                    bytes_left: int = entry.size
                    while bytes_left > 0:
                        bytes_to_read = min(4096, bytes_left)
                        section_file.write(image_file.read(bytes_to_read))
                        bytes_left -= bytes_to_read

    @classmethod
    def from_manifest(cls, manifest_path: str | Path) -> Self:
        ...

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

    def checksum(self) -> list[int]:
        results: list[int] = []
        with self.path.open('rb') as f:
            for offset, checksum in zip(
                    range(0, self.metadata.data_size, self.metadata.checksum_block_size),
                    self.metadata.checksums
            ):
                f.seek(offset)
                checksum = simple_checksum(f, self.metadata.checksum_block_size)
                results.append(checksum)
        return results
