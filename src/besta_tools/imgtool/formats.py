from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from io import BufferedReader
from itertools import zip_longest
from pathlib import Path
from typing import Annotated, Any, Protocol, Self, cast, TYPE_CHECKING, override

if TYPE_CHECKING:
    from _typeshed import MaybeNone, SupportsWrite

import math
import re
import shutil

import yaml

from construct import (
    Array,
    Const,
    Check,
    IfThenElse,
    Int32ul,
    Int64ul,
    Padded,
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
from marshmallow_dataclass import class_schema as mm_class_schema

from filetype import guess, add_type as ft_add_type
from .filetype import TYPES

from ..common.formats import CsChecksumValue, ChecksumValue
from ..common.utils import BinaryBuilder, Checksum, Fragment, align, copyfileobjex, div_round_up, generate_padding
from ..common.probe import probe_image as common_probe_image, ProbeResultData, ProbeError, IMAGE_INDEX_V2_MAGIC


for t in TYPES:
    ft_add_type(t)


if TYPE_CHECKING:
    class SupportsTell(Protocol):
        def tell(self) -> int: ...


    class BuilderIoObject[T_contra](SupportsTell, SupportsWrite[T_contra], Protocol):
        pass


    class ImageMetadataProtocol(Protocol):
        image_name: str
        image_version: str
        content_size: int
        data_size: int
        checksum_block_size: int
        checksums: list[ChecksumValue]


    class ImageIndexProtocol(Protocol):
        @property
        def entries(self) -> Sequence[ImageIndexEntryProtocol]: ...
        def count_entries(self) -> int: ...


    class ImageIndexEntryProtocol(Protocol):
        offset: int
        size: int


IMAGE_TYPE_MAP: dict[str, int] = {
    'system-data': 0x0001801d,
    'system-data-2': 0x0001841d,
    'application-data': 0x00000000,
}

IMAGE_TYPE_MAP_R = {v: k for k, v in IMAGE_TYPE_MAP.items()}

RE_IMAGE_TYPE = re.compile(r'^(?:key:(\d+|0x[A-Fa-f0-9]+|0o[0-7]+|0b[0-1]+))$')

MAGIC_PROBE_SIZE = 65536  # 8KiB, as per the default of filetype


def guess_block_size_image_v2(f: BufferedReader, search_limit: int = 0x100000, step_size: int = 16) -> int:
    for offset in range(0, search_limit, step_size):
        f.seek(offset)
        if f.read(step_size)[:4] == IMAGE_INDEX_V2_MAGIC:
            return offset
    raise ProbeError('Cannot determine block size.')


def probe_image(f: BufferedReader, search_limit: int = 0x100000, step_size: int = 16) -> ProbeResultData:
    result = common_probe_image(f, search_limit=search_limit, step_size=step_size)
    if not isinstance(result, ProbeResultData):
        raise ProbeError('Image is not a data image.')
    return result


def construct_from_image_file(path: str | Path) -> AbstractImageFile:
    image: AbstractImageFile
    path = Path(path)
    with path.open('rb') as f:
        probe = probe_image(f)
        if probe.header_format_version == 2:
            image = ImageFileV2.load(path)
        elif probe.header_format_version == 1:
            image = ImageFileV1.load(path)
        else:
            raise ProbeError(f'Unhandled image file type {probe}')
        return image


def construct_from_manifest(path: str | Path) -> AbstractImageFile:
    path = Path(path)
    reader: type[AbstractImageFile]
    for reader in (ImageFileV1, ImageFileV2):
        try:
            return reader.from_manifest(path)
        except ProbeError:
            continue
        except Exception as e:
            raise ProbeError(str(e)) from e
    raise ProbeError('Unhandled image metadata format version.')


@dataclass
class ImageMetadataV1(DataclassMixin):
    image_name: str = csfield(PaddedString(16, 'ascii'))
    image_version: str = csfield(PaddedString(12, 'ascii'))
    content_size: int = csfield(Int32ul)
    data_size: int = csfield(Int32ul)
    checksum_block_size: int = csfield(Int32ul)
    checksums: list[ChecksumValue] = csfield(
        Padded(
            0xd8,
            IfThenElse(
                this.checksum_block_size != 0,
                Array(lambda c: div_round_up(c.data_size, c.checksum_block_size), CsChecksumValue),
                Array(0, CsChecksumValue),
            )
        )
    )


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
        Padded(
            0x3f0,
            RepeatUntil(
                lambda obj, lst, ctx: obj.is_sentinel(),
                CsImageIndexEntryV1
            ),
            b'\xff',
        )
    )

    def count_entries(self) -> int:
        result = 0
        for e in self.entries:
            if e.is_sentinel():
                break
            result += 1
        return result


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

    def count_entries(self) -> int:
        return len(self.entries)


CsImageIndexV2 = DataclassStruct(ImageIndexV2)


@dataclass
class ImageManifestSection:
    path: str
    align: int = field(default=1, metadata={'required': False})


def type_validator(val: str) -> None:
    if val not in IMAGE_TYPE_MAP.keys() and RE_IMAGE_TYPE.match(val) is None:
        raise ValidationError(f'Invalid type value {repr(val)}')


@dataclass
class ImageManifest:
    manifest_version: Annotated[int | None, mm_fields.Field(load_default=None)]
    header_format_version: int
    index_format_version: Annotated[int | None, mm_fields.Field(load_default=None)]
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


class AbstractImageFile(ABC):
    '''
    `ImageFileV*` interface and common routines.
    '''

    path: Path
    'Path to the image file if the image file exists, or the path to the manifest file if the image file is yet to be built.'
    is_file: bool
    'True if object is backed by a real image file, False if object is backed by separate files listed in the manifest.'
    manifest: ImageManifest | MaybeNone
    guessed_mime: list[str] | None

    @property
    @abstractmethod
    def metadata(self) -> ImageMetadataProtocol:
        '''
        Generic metadata getter.
        Must be manually connected to the format-specific metadata object.
        '''
        raise NotImplementedError()

    @property
    @abstractmethod
    def index(self) -> ImageIndexProtocol:
        '''
        Generic index getter.
        Must be manually connected to the format-specific index object.
        '''
        raise NotImplementedError()

    @abstractmethod
    def _build_manifest(self) -> None:
        '''
        Define how the manifest should be built from parsed metadata and index.
        Must be filled with format-specific implementation.
        '''
        raise NotImplementedError()

    @abstractmethod
    def _emit_data(self, fout: BuilderIoObject[bytes], pad_to_size: int | None = None) -> None:
        '''
        Define how metadata and index should be assembled into an image file.
        Must be filled with format-specific implementation.
        '''
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def load(cls, image_path: str | Path) -> Self:
        '''
        Parse and construct metadata and index from an image file.
        Must be filled with format-specific implementation.
        '''
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def from_manifest(cls, manifest_path: str | Path) -> Self:
        '''
        Construct metadata and index from a manifest.
        Must be filled with format-specific implementation.
        '''
        raise NotImplementedError()

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


@dataclass
class ImageFileV1(AbstractImageFile):
    path: Path
    is_file: bool
    metadata_v1: ImageMetadataV1
    index_v1: ImageIndexV1
    # manifest is typed as None because we have a custom default value factory
    # that depends on the rest of the object states in case it is not passed
    # on initialization. In practice this value will never be None.
    manifest: ImageManifest | MaybeNone = field(default=None)
    guessed_mime: list[str] | None = field(default=None)

    def __post_init__(self) -> None:
        if self.manifest is None:
            self._build_manifest()

    @property
    @override
    def metadata(self) -> ImageMetadataV1:
        return self.metadata_v1

    @property
    @override
    def index(self) -> ImageIndexV1:
        return self.index_v1

    @override
    def _build_manifest(self) -> None:
        def _gen_section_info(entries: list[ImageIndexEntryV1]):
            for i, entry in enumerate(entries):
                if entry.is_sentinel():
                    break
                probe_size = min(entry.size, MAGIC_PROBE_SIZE)
                with self.path.open('rb') as f:
                    probe_mime: str
                    probe_ext: str

                    f.seek(entry.offset)
                    if entry.size == 0:
                        probe_mime = 'inode/x-empty'
                        probe_ext = 'bin'
                    else:
                        probe_data = f.read(probe_size)
                        probe_result = guess(probe_data)
                        if probe_result is None:
                            probe_mime = 'application/octet-stream'
                            probe_ext = 'bin'
                        else:
                            probe_mime = probe_result.mime
                            probe_ext = probe_result.extension
                yield f'sections/{i:08x}.{probe_ext}', probe_mime

        # Alignment value by definition must be integer multiples of every data offset value.
        # If there's only one data entry, disable alignment.
        if len(self.index_v1.entries) <= 1:
            align = 1
        else:
            align = math.gcd(*(e.offset for e in filter((lambda ee: not ee.is_sentinel() and ee.offset != 0), self.index_v1.entries)))
            if align == 0:
                align = 1

        section_info = tuple(_gen_section_info(self.index_v1.entries))
        sections: list[ImageManifestSection] = [
            ImageManifestSection(name, align=align) for name, _ in section_info
        ]

        self.guessed_mime = [mime for _, mime in section_info]
        self.manifest = ImageManifest(
            manifest_version=None,
            header_format_version=1,
            index_format_version=None,
            name=self.metadata_v1.image_name,
            version_string=self.metadata_v1.image_version,
            type=IMAGE_TYPE_MAP_R.get(self.index_v1.image_type, f'key:0x{self.index_v1.image_type:x}'),
            block_size=0x100,
            checksum_block_size=self.metadata_v1.checksum_block_size,
            content_size=self.metadata_v1.content_size,
            data_size=self.metadata_v1.data_size,
            header_size=0x500,
            sections=sections,
        )

    @override
    def _emit_data(self, fout: BuilderIoObject[bytes], pad_to_size: int | None = None):
        assert self.manifest is not None

        metadata = CsImageMetadataV1.build(self.metadata_v1)
        index = CsImageIndexV1.build(self.index_v1)
        fout.write(metadata)
        fout.write(index)

        if not self.is_file:
            for section, entry in zip(self.manifest.sections, self.index_v1.entries):
                with open(self.path.parent / section.path, 'rb') as fsec:
                    assert entry.offset == fout.tell(), ('Attempting to place section at unexpected offset. '
                                                         'This is likely a bug of the index builder.')
                    shutil.copyfileobj(fsec, fout)
                    fout.write(generate_padding(fout.tell(), section.align, pad_byte=0xff))

        else:
            with self.path.open('rb') as image_file:
                for section, entry in zip(self.manifest.sections, self.index_v1.entries):
                    image_file.seek(entry.offset)
                    copyfileobjex(image_file, fout, limit=entry.size)
                    fout.write(generate_padding(fout.tell(), section.align, pad_byte=0xff))

        if fout.tell() < self.metadata_v1.content_size:
            fout.write(generate_padding(fout.tell(), self.metadata_v1.content_size if pad_to_size is None else pad_to_size, pad_byte=0xff))

    @override
    @classmethod
    def load(cls, image_path: str | Path) -> Self:
        image_path = Path(image_path)
        with image_path.open('rb') as f:
            metadata = CsImageMetadataV1.parse_stream(f)
            index = CsImageIndexV1.parse_stream(f)

        return cls(image_path, True, metadata, index)

    @override
    @classmethod
    def from_manifest(cls, manifest_path: str | Path) -> Self:
        # This is only used for offset calculation and not for actual binary building
        bb = BinaryBuilder()

        manifest_path = Path(manifest_path)
        with manifest_path.open('r') as manifest_file:
            manifest = cast(ImageManifest, MmImageManifest().load(cast(dict[str, Any], yaml.safe_load(manifest_file))))  # pyright: ignore[reportInvalidCast]

        if manifest.header_format_version != 1:
            raise ProbeError('Header format version must be 1.')

        nchecksums = div_round_up(manifest.data_size, manifest.checksum_block_size)

        header_size_v1 = CsImageIndexV1.sizeof() + CsImageMetadataV1.sizeof()
        bb.append(header_size_v1)

        index_entries: list[ImageIndexEntryV1] = []
        frag_entries: list[Fragment] = []
        for section in manifest.sections:
            path = manifest_path.parent / Path(section.path)
            real_size = path.stat().st_size
            frag_section = bb.append(align(real_size, section.align))
            frag_entries.append(frag_section)
            index_entries.append(ImageIndexEntryV1(offset=frag_section.offset, size=real_size))
        index_entries.append(ImageIndexEntryV1.sentinel())

        dummy_checksums = [ChecksumValue(checksum=0) for _ in range(nchecksums)]
        metadata = ImageMetadataV1(
            image_name=manifest.name,
            image_version=manifest.version_string,
            content_size=manifest.content_size,
            data_size=manifest.data_size,
            checksum_block_size=manifest.checksum_block_size,
            checksums=dummy_checksums,
        )

        index = ImageIndexV1(
            image_type=manifest.parse_type_key(),
            entries=index_entries,
        )

        result = cls(
            path=manifest_path,
            is_file=False,
            metadata_v1=metadata,
            index_v1=index,
            manifest=manifest,
        )

        result.fix_checksum()

        return result


@dataclass
class ImageFileV2(AbstractImageFile):
    path: Path
    is_file: bool
    metadata_v2: ImageMetadataV2
    index_v2: ImageIndexV2
    # manifest is typed as None because we have a custom default value factory
    # that depends on the rest of the object states in case it is not passed
    # on initialization. In practice this value will never be None.
    manifest: ImageManifest | MaybeNone = field(default=None)
    guessed_mime: list[str] | None = field(default=None)

    def __post_init__(self) -> None:
        if self.manifest is None:
            self._build_manifest()

    @property
    @override
    def metadata(self) -> ImageMetadataV2:
        return self.metadata_v2

    @property
    @override
    def index(self) -> ImageIndexV2:
        return self.index_v2

    @override
    def _build_manifest(self) -> None:
        def _gen_section_info(entries: list[ImageIndexEntryV2]):
            for i, entry in enumerate(entries):
                probe_size = min(entry.size, MAGIC_PROBE_SIZE)
                with self.path.open('rb') as f:
                    probe_mime: str
                    probe_ext: str

                    f.seek(entry.offset)
                    if entry.size == 0:
                        probe_mime = 'inode/x-empty'
                        probe_ext = 'bin'
                    else:
                        probe_data = f.read(probe_size)
                        probe_result = guess(probe_data)
                        if probe_result is None:
                            probe_mime = 'application/octet-stream'
                            probe_ext = 'bin'
                        else:
                            probe_mime = probe_result.mime
                            probe_ext = probe_result.extension
                yield f'sections/{i:08x}.{probe_ext}', probe_mime

        with self.path.open('rb') as f:
            guessed_block_size = guess_block_size_image_v2(f)

        # Alignment value by definition must be integer multiples of every data offset value.
        # If there's only one data entry, disable alignment.
        if len(self.index_v2.entries) <= 1:
            align = 1
        else:
            align = math.gcd(*(e.offset for e in filter((lambda ee: ee.offset != 0), self.index_v2.entries)))
            if align == 0:
                align = 1

        section_info = tuple(_gen_section_info(self.index_v2.entries))
        sections: list[ImageManifestSection] = [
            ImageManifestSection(name, align=align) for name, _ in section_info
        ]

        self.guessed_mime = [mime for _, mime in section_info]
        self.manifest = ImageManifest(
            manifest_version=None,
            header_format_version=2,
            index_format_version=self.index_v2.format_version,
            name=self.metadata_v2.image_name,
            version_string=self.metadata_v2.image_version,
            type=IMAGE_TYPE_MAP_R.get(self.metadata_v2.image_type_key, f'key:0x{self.metadata_v2.image_type_key:x}'),
            block_size=guessed_block_size,
            checksum_block_size=self.metadata_v2.checksum_block_size,
            content_size=self.metadata_v2.content_size,
            data_size=self.metadata_v2.data_size,
            header_size=self.index_v2.entries[0].offset if len(self.index_v2.entries) > 0 else None,
            sections=sections,
        )

    @override
    def _emit_data(self, fout: BuilderIoObject[bytes], pad_to_size: int | None = None):
        assert self.manifest is not None

        metadata = CsImageMetadataV2.build(self.metadata_v2)
        index = CsImageIndexV2.build(self.index_v2)
        fout.write(metadata)
        fout.write(generate_padding(fout.tell(), self.manifest.block_size))
        fout.write(index)

        assert self.manifest.header_size is None or fout.tell() <= self.manifest.header_size, 'BUG in metadata builder: Header size over limit.'

        fout.write(generate_padding(fout.tell(), self.manifest.block_size if self.manifest.header_size is None else self.manifest.header_size, pad_byte=0xff))

        if not self.is_file:
            for section, entry in zip(self.manifest.sections, self.index_v2.entries):
                with open(self.path.parent / section.path, 'rb') as fsec:
                    assert entry.offset == fout.tell(), ('Attempting to place section at unexpected offset. '
                                                         'This is likely a bug of the index builder.')
                    shutil.copyfileobj(fsec, fout)
                    fout.write(generate_padding(fout.tell(), section.align, pad_byte=0xff))

        else:
            with self.path.open('rb') as image_file:
                for section, entry in zip(self.manifest.sections, self.index_v2.entries):
                    image_file.seek(entry.offset)
                    copyfileobjex(image_file, fout, limit=entry.size)
                    fout.write(generate_padding(fout.tell(), section.align, pad_byte=0xff))

        if fout.tell() < self.metadata_v2.content_size:
            fout.write(generate_padding(fout.tell(), self.metadata_v2.content_size if pad_to_size is None else pad_to_size, pad_byte=0xff))

    @override
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

    @override
    @classmethod
    def from_manifest(cls, manifest_path: str | Path) -> Self:
        # This is only used for offset calculation and not for actual binary building
        bb = BinaryBuilder()

        manifest_path = Path(manifest_path)
        with manifest_path.open('r') as manifest_file:
            manifest = cast(ImageManifest, MmImageManifest().load(cast(dict[str, Any], yaml.safe_load(manifest_file))))  # pyright: ignore[reportInvalidCast]

        if manifest.header_format_version != 1:
            raise ProbeError('Header format version must be 1.')

        if manifest.index_format_version is None:
            raise RuntimeError('Index format version must be set for image format V2.')

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
            metadata_v2=metadata,
            index_v2=index,
            manifest=manifest,
        )

        result.fix_checksum()

        return result
