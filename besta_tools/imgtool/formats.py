from io import BufferedReader
from itertools import zip_longest
import re
from typing import Annotated, Any, Protocol, Self, cast, TYPE_CHECKING
if TYPE_CHECKING:
    from _typeshed import SupportsWrite

import math
import shutil

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from construct import (
    Array,
    Const,
    Check,
    IfThenElse,
    Int32ul,
    Int64ul,
    PaddedString,
    Padding,
    Rebuild,
    RepeatUntil,
    this,
    len_
)
from construct_typed import DataclassMixin, DataclassStruct, csfield
from marshmallow import ValidationError
from marshmallow import fields as mm_fields
from marshmallow_dataclass import dataclass as mm_dataclass
from marshmallow_dataclass import class_schema as mm_class_schema

from filetype import guess_extension

from ..common.formats import CsChecksumValue, ChecksumValue
from ..common.utils import BinaryBuilder, Checksum, Fragment, align, copyfileobjex, is_strictly_nul_terminated, div_round_up, generate_padding


if TYPE_CHECKING:
    class SupportsTell(Protocol):
        def tell(self) -> int: ...


    class BuilderIoObject[T_contra](SupportsTell, SupportsWrite[T_contra], Protocol):
        pass


IMAGE_TYPE_SYSTEM_DATA_MAGIC = 0x0001801d
IMAGE_INDEX_V2_MAGIC = b'\xaa\x55\xaa\x55'
IMAGE_INDEX_V1_MAGIC = IMAGE_TYPE_SYSTEM_DATA_MAGIC.to_bytes(4, 'little')

IMAGE_TYPE_MAP: dict[str, int] = {
    'system-data': 0x0001801d,
    'application-data': 0x00000000,
}

IMAGE_TYPE_MAP_R = {v: k for k, v in IMAGE_TYPE_MAP.items()}

RE_IMAGE_TYPE = re.compile(r'^(?:key:(\d+|0x[A-Fa-f0-9]+|0o[0-7]+|0b[0-1]+))$')

MAGIC_PROBE_SIZE = 8192  # 8KiB, as per the default of filetype


def guess_block_size_image_v2(f: BufferedReader, search_limit: int = 0x100000, step_size: int = 16) -> int:
    for offset in range(0, search_limit, step_size):
        f.seek(offset)
        if f.read(step_size)[:4] == IMAGE_INDEX_V2_MAGIC:
            return offset
    raise RuntimeError('Cannot determine block size.')


@dataclass
class ProbeResult:
    header_format_version: int
    index_type: int
    block_size: int


def probe_image(f: BufferedReader, search_limit: int = 0x100000, step_size: int = 16) -> ProbeResult:
    header_format_version = None
    block_size = None
    index_type = None

    f.seek(16)
    seq1 = f.read(16)
    seq2 = f.read(16)
    # seq2 (os version string) can also be empty for data header format version 2
    if is_strictly_nul_terminated(seq1) and (is_strictly_nul_terminated(seq2) or not any(seq2)):
        header_format_version = 2
    elif is_strictly_nul_terminated(seq1[:14]) and not is_strictly_nul_terminated(seq2):
        header_format_version = 1
    for offset in range(0, search_limit, step_size):
        f.seek(offset)
        marker = f.read(step_size)[:4]
        if marker == IMAGE_INDEX_V2_MAGIC:
            index_type = 2
            block_size = offset
        elif marker == IMAGE_INDEX_V1_MAGIC:
            index_type = 1
            block_size = offset

    if header_format_version is None:
        raise RuntimeError('Cannot determine format version.')
    if index_type is None:
        raise RuntimeError('Cannot determine index type.')
    if block_size is None:
        raise RuntimeError('Cannot determine block size.')
    
    return ProbeResult(header_format_version, index_type, block_size)


@dataclass
class ImageMetadataV1(DataclassMixin):
    image_name: str = csfield(PaddedString(16, 'ascii'))
    image_version: str = csfield(PaddedString(12, 'ascii'))
    content_size: int = csfield(Int32ul)
    data_size: int = csfield(Int32ul)
    checksum_block_size: int = csfield(Int32ul)
    checksums: list[ChecksumValue] = csfield(IfThenElse(
        this.checksum_block_size != 0,
        Array(lambda c: div_round_up(c.data_size, c.checksum_block_size), CsChecksumValue),
        Array(0, CsChecksumValue),
    ))


CsImageMetadataV1 = DataclassStruct(ImageMetadataV1)


@dataclass
class ImageMetadataV2(DataclassMixin):
    image_name: str = csfield(PaddedString(16, 'ascii'))
    image_version: str = csfield(PaddedString(16, 'ascii'))
    os_version: str = csfield(PaddedString(16, 'ascii'))
    content_size: int = csfield(Int64ul)
    data_size: int = csfield(Int64ul)
    checksum_block_size: int = csfield(Int32ul)
    image_type_key: int = csfield(Int32ul)
    _padding_0x48: None = csfield(Padding(24))
    checksums: list[ChecksumValue] = csfield(IfThenElse(
        this.checksum_block_size != 0,
        Array(lambda c: div_round_up(c.data_size, c.checksum_block_size), CsChecksumValue),
        Array(0, CsChecksumValue),
    ))


CsImageMetadataV2 = DataclassStruct(ImageMetadataV2)


# There's a bug in construct 2.9+ that prevented dynamic sizeof() being calculated.
# Hardcode this for now.
IMAGE_METADATA_V1_SIZEOF = 0x28
IMAGE_METADATA_V2_SIZEOF = 0x60


@dataclass
class ImageIndexEntryV1(DataclassMixin):
    offset: int = csfield(Int32ul)
    size: int = csfield(Int32ul)

    @classmethod
    def sentinel(cls) -> Self:
        '''
        Build a sentinel value i.e. ImageIndexEntryV1((0xffffffff, 0xffffffff).
        '''
        return cls(0xffffffff, 0xffffffff)

    def is_sentinel(self) -> bool:
        '''
        Return True if the entry is a sentinel value.
        '''
        return self.offset == 0xffffffff and self.size == 0xffffffff


CsImageIndexEntryV1 = DataclassStruct(ImageIndexEntryV1)


@dataclass
class ImageIndexEntryV2(DataclassMixin):
    offset: int = csfield(Int64ul)
    size: int = csfield(Int64ul)
    _integrity: None = csfield(Check(this.offset != (1 << 64) - 1 and this.size != (1 << 64) - 1))


CsImageIndexEntryV2 = DataclassStruct(ImageIndexEntryV2)


@dataclass
class ImageIndexV1(DataclassMixin):
    image_type: int = csfield(Int32ul)
    _reserved: bytes = csfield(Const(b'\xff' * 12))
    # This will keep the sentinel value at both the build time and parse time,
    # therefore it's required to include a
    # ImageIndexEntryV1(0xffffffff, 0xffffffff) at the end of the list.
    entries: list[ImageIndexEntryV1] = csfield(
        RepeatUntil(
            lambda obj, lst, ctx: obj.is_sentinel(),
            CsImageIndexEntryV1
        )
    )


CsImageIndexV1 = DataclassStruct(ImageIndexV1)


IMAGE_INDEX_V2_VERSIONS: set[int] = {
    0x20090828,
    0x20081202,
}


IMAGE_INDEX_V2_SIZEOF = 0x40


@dataclass
class ImageIndexV2(DataclassMixin):
    magic: bytes = csfield(Const(IMAGE_INDEX_V2_MAGIC))
    header_size: int = csfield(Const(IMAGE_INDEX_V2_SIZEOF, Int32ul))
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


def type_validator(val: str) -> None:
    if val not in IMAGE_TYPE_MAP.keys() and RE_IMAGE_TYPE.match(val) is None:
        raise ValidationError(f'Invalid type value {repr(val)}')


@mm_dataclass
class ImageManifest:
    header_format_version: int
    index_format_version: int
    name: str
    version_string: str
    type: Annotated[
        str,
        mm_fields.String(validate=type_validator)
    ]
    block_size: int
    checksum_block_size: int
    content_size: int
    data_size: int
    header_size: Annotated[int | None, mm_fields.Field(load_default=None)]
    sections: list[ImageManifestSection]

    def parse_type_key(self) -> int:
        if self.type in IMAGE_TYPE_MAP:
            return IMAGE_TYPE_MAP[self.type]
        m = RE_IMAGE_TYPE.match(self.type)
        if m is None:
            raise ValueError(f'Unknown type {repr(self.type)}')
        return int(m.group(1))


MmImageManifest = mm_class_schema(ImageManifest)


@dataclass
class ImageFileV2:
    path: Path
    'Path to the image file if the image file exists, or the path to the manifest file if the image file is yet to be built.'
    is_file: bool
    'True if object is backed by a real image file, False if object is backed by separate files listed in the manifest.'
    metadata: ImageMetadataV2
    index: ImageIndexV2
    # manifest is typed as None because we have a custom default value factory
    # that depends on the rest of the object states in case it is not passed
    # on initialization. In practice this value will never be None.
    manifest: ImageManifest | None = field(default=None)

    def __post_init__(self) -> None:
        if self.manifest is None:
            self._build_manifest()

    def _build_manifest(self) -> None:
        def _gen_section_name(entries: list[ImageIndexEntryV2]):
            for i, entry in enumerate(entries):
                probe_size = min(entry.size, MAGIC_PROBE_SIZE)
                with self.path.open('rb') as f:
                    f.seek(entry.offset)
                    probe_data = f.read(probe_size)
                    probe_result: str = guess_extension(probe_data) or 'bin'
                yield f'sections/{i:08x}.{probe_result}'

        with self.path.open('rb') as f:
            guessed_block_size = guess_block_size_image_v2(f)

        # Alignment value by definition must be integer multiples of every data offset value.
        # If there's only one data entry, disable alignment.
        if len(self.index.entries) <= 1:
            align = 1
        else:
            align = math.gcd(*(e.offset for e in filter((lambda ee: ee.offset != 0), self.index.entries)))
            if align == 0:
                align = 1

        sections: list[ImageManifestSection] = [
            ImageManifestSection(name, align=align) for name in _gen_section_name(self.index.entries)
        ]

        self.manifest = ImageManifest(
            header_format_version=2,
            index_format_version=self.index.format_version,
            name=self.metadata.image_name,
            version_string=self.metadata.image_version,
            type=IMAGE_TYPE_MAP_R.get(self.metadata.image_type_key, f'key:0x{self.metadata.image_type_key:x}'),
            block_size=guessed_block_size,
            checksum_block_size=self.metadata.checksum_block_size,
            content_size=self.metadata.content_size,
            data_size=self.metadata.data_size,
            header_size=self.index.entries[0].offset if len(self.index.entries) > 0 else None,
            sections=sections,
        )

    def _emit_data(self, fout: 'BuilderIoObject[bytes]', pad_to_size: int | None = None):
        assert self.manifest is not None

        metadata = CsImageMetadataV2.build(self.metadata)
        index = CsImageIndexV2.build(self.index)
        fout.write(metadata)
        fout.write(generate_padding(fout.tell(), self.manifest.block_size))
        fout.write(index)

        assert self.manifest.header_size is None or fout.tell() <= self.manifest.header_size, 'BUG in metadata builder: Header size over limit.'

        fout.write(generate_padding(fout.tell(), self.manifest.block_size if self.manifest.header_size is None else self.manifest.header_size, pad_byte=0xff))

        if not self.is_file:
            for section, entry in zip(self.manifest.sections, self.index.entries):
                with open(self.path.parent / section.path, 'rb') as fsec:
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

        if fout.tell() < self.metadata.content_size:
            fout.write(generate_padding(fout.tell(), self.metadata.content_size if pad_to_size is None else pad_to_size, pad_byte=0xff))

    @classmethod
    def load(cls, image_path: str | Path) -> Self:
        image_path = Path(image_path)
        with image_path.open('rb') as f:
            block1_offset = guess_block_size_image_v2(f)
            f.seek(0)
            metadata = CsImageMetadataV2.parse_stream(f)
            f.seek(block1_offset)
            index = CsImageIndexV2.parse_stream(f)

        return cls(image_path, True, metadata, index)

    @classmethod
    def from_manifest(cls, manifest_path: str | Path) -> Self:
        # This is only used for offset calculation and not for actual binary building
        bb = BinaryBuilder()

        manifest_path = Path(manifest_path)
        with manifest_path.open('r') as manifest_file:
            manifest = cast(ImageManifest, MmImageManifest().load(cast(dict[str, Any], yaml.safe_load(manifest_file))))

        assert manifest.header_format_version == 2, 'Header format version must be 2.'

        nchecksums = div_round_up(manifest.data_size, manifest.checksum_block_size)

        header_align = manifest.block_size if manifest.header_size is None else manifest.header_size
        header_size_actual = align(IMAGE_METADATA_V2_SIZEOF + CsChecksumValue.sizeof() * nchecksums, manifest.block_size) + IMAGE_INDEX_V2_SIZEOF + CsImageIndexEntryV2.sizeof() * len(manifest.sections)
        header_size_padded = align(header_size_actual, header_align)
        if manifest.header_size is not None and manifest.header_size < header_size_actual:
            raise RuntimeError(f'Header allocation over limit (max allowed: 0x{manifest.header_size:x}, actual size: 0x{header_size_actual:x}). Refusing to process further.')
        bb.append(header_size_padded)

        index_entries: list[ImageIndexEntryV2] = []
        frag_entries: list[Fragment] = []
        for section in manifest.sections:
            path = manifest_path.parent / Path(section.path)
            real_size = path.stat().st_size
            frag_section = bb.append(align(real_size, section.align))
            frag_entries.append(frag_section)
            index_entries.append(ImageIndexEntryV2(offset=frag_section.offset, size=real_size))

        dummy_checksums = [ChecksumValue(checksum=0) for _ in range(nchecksums)]
        metadata = ImageMetadataV2(
            image_name=manifest.name,
            image_version=manifest.version_string,
            os_version='',
            content_size=manifest.content_size,
            data_size=manifest.data_size,
            checksum_block_size=manifest.checksum_block_size,
            image_type_key=manifest.parse_type_key(),
            checksums=dummy_checksums,
        )

        index = ImageIndexV2(
            format_version=manifest.index_format_version,
            entries=index_entries,
        )

        result = cls(
            path=manifest_path,
            is_file=False,
            metadata=metadata,
            index=index,
            manifest=manifest,
        )

        result.fix_checksum()

        return result

    def fix_checksum(self) -> None:
        assert self.manifest is not None, 'BUG: Missing manifest object.'

        checksum_size = div_round_up(self.metadata.data_size, self.metadata.checksum_block_size) * self.metadata.checksum_block_size
        checksum = Checksum(self.manifest.checksum_block_size)

        self._emit_data(checksum, pad_to_size=checksum_size)

        d = checksum.digest()
        if len(d) != 0:
            # Each non-zero checksum value adds up to 0x200 instead of 0
            fixup = sum(0x200 for c in d if c != 0)
            d[0] = (d[0] + fixup) & 0xffff

        self.metadata.checksums = [ChecksumValue(c) for c in d]

    def build(self, output: str | Path) -> None:
        if self.manifest is None:
            raise ValueError('Incomplete image file object. Building not supported.')

        output = Path(output)

        with output.open('wb') as fout:
            self._emit_data(fout)

    def extract(self, output: str | Path) -> None:
        if self.manifest is None:
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
                    copyfileobjex(image_file, section_file, limit=entry.size)

    def verify(self) -> list[bool]:
        if not self.is_file:
            raise RuntimeError('Calling verify() on a yet to be built image does not make sense.')
        actuals = self.checksum()
        return [actual == expected.checksum if expected is not None else False for actual, expected in zip_longest(actuals, self.metadata.checksums)]

    def checksum(self) -> list[int]:
        '''
        If this object is created on a image file, compute and print the checksum block.
        Otherwise, the precomputed checksum block during manifest load is returned instead.
        '''
        if not self.is_file:
            return [checksum.checksum for checksum in self.metadata.checksums]

        declared_blocks = div_round_up(self.metadata.data_size, self.metadata.checksum_block_size)
        with self.path.open('rb') as f:
            checksum = Checksum(self.metadata.checksum_block_size)
            while True:
                data = f.read(0x100000)
                if len(data) == 0:
                    break
                checksum.update(data)

        d = checksum.digest()
        pad_blocks = declared_blocks - len(d)
        if pad_blocks > 0:
            d.extend([0] * pad_blocks)

        return d
