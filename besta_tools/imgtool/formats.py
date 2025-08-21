from typing import BinaryIO, Self, cast, TYPE_CHECKING
if TYPE_CHECKING:
    from construct import Context

import math
import shutil

from dataclasses import dataclass, field
from pathlib import Path

#import filetype
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
from ..common.utils import simple_checksum, copyfileobjex
from ..elf2bestape.utils import generate_padding


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
    _padding_0x48: None = csfield(Padding(24))
    checksums: list[ChecksumValue] = csfield(IfThenElse(
        this.checksum_block_size != 0,
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
    is_file: bool
    metadata: ImageMetadataV2 | None = field(default=None)
    index: ImageIndexV2 | None = field(default=None)
    manifest: ImageManifest | None = field(default=None)

    def __post_init__(self):
        if self.manifest is None:
            self._build_manifest()

    def _build_manifest(self):
        with self.path.open('rb') as f:
            guessed_block_size = guess_block_size_image_v2(f)

        align = math.gcd(*(e.offset for e in filter((lambda ee: ee.offset != 0), self.index.entries)))
        if align == 0:
            align = 1

        sections: list[ImageManifestSection] = [
            ImageManifestSection(f'sections/{i:08x}.bin', align=align) for i in range(self.index.nentries)
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

        return cls(image_path, is_file=True, metadata=metadata, index=index)

    def build(self, output: str | Path) -> None:
        if self.metadata is None or self.manifest is None or self.index is None:
            raise ValueError('Incomplete image file object. Building not supported.')
        
        output = Path(output)

        metadata = CsImageMetadataV2.build(self.metadata)
        index = CsImageIndexV2.build(self.index)

        with output.open('wb') as fout:
            fout.write(metadata)
            fout.write(generate_padding(fout.tell(), self.manifest.block_size))
            fout.write(index)
            fout.write(generate_padding(fout.tell(), self.manifest.block_size, pad_byte=0xff))

            if not self.is_file:
                for section, entry in zip(self.manifest.sections, self.index.entries):
                    with open(section.path, 'rb') as fsec:
                        assert entry.offset == fout.tell(), ('Attempting to place section at unexpected offset. '
                                                             'This is likely a bug of the index builder.')
                        shutil.copyfileobj(fsec, fout)
                        fout.write(generate_padding(fout.tell(), section.align, pad_byte=0xff))

            else:
                with self.path.open('rb') as image_file:
                    for section, entry in zip(self.manifest.sections, self.index.entries):
                        image_file.seek(entry.offset)
                        copyfileobjex(image_file, fout, limit=entry.size)
                        fout.write(generate_padding(fout.tell(), section.align, pad_byte=0xff))

            fout.write(generate_padding(fout.tell(), self.metadata.content_size, pad_byte=0xff))

    def extract(self, output: str | Path) -> None:
        if self.manifest is None or self.index is None:
            raise ValueError('Incomplete image file object. Extraction not supported.')
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
                    copyfileobjex(image_file, section_file, limit=entry.size)

    @classmethod
    def from_manifest(cls, manifest_path: str | Path) -> Self:
        # TODO create index and metadata out of a loaded manifest file
        ...

    def verify(self) -> list[bool]:
        if self.metadata is None:
            raise ValueError('Missing metadata. Cannot verify. Has the file been correctly parsed?')
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
        if self.metadata is None:
            raise ValueError('Missing metadata. Cannot verify. Has the file been correctly parsed?')
        results: list[int] = []
        with self.path.open('rb') as f:
            for offset, _checksum in zip(
                    range(0, self.metadata.data_size, self.metadata.checksum_block_size),
                    self.metadata.checksums
            ):
                f.seek(offset)
                checksum = simple_checksum(f, self.metadata.checksum_block_size)
                results.append(checksum)
        return results
