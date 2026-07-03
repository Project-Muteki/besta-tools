from dataclasses import dataclass
from enum import Enum, auto
from io import BufferedReader
from typing import Annotated, Literal, NamedTuple, TypeAlias

from marshmallow import fields as mm_fields
from marshmallow_dataclass import class_schema as mm_class_schema

from besta_tools.common.probe import ProbeError, ProbeResultData, ProbeResultKernel, probe_image
from besta_tools.imgtool.formats import CsImageMetadataV1, CsImageMetadataV2, ImageMetadataV1, ImageMetadataV2


# This has to be declared using the old style syntax (plain or TypeAlias
# instead of the 3.12+ type T = U syntax) or marshmallow_dataclass won't
# know what this is.
PartitionManifestTypeId: TypeAlias = Literal[
    'bootloader',
    'kernel',
    'system-data',
    'application-data',
    'misc-data',
    'user-data',
    'tad',
]


class PartitionType(Enum):
    KERNEL = auto()
    SYS_DATA = auto()
    APP_DATA = auto()
    UNK_DATA = auto()
    #USER_DATA = auto()
    TAD = auto()


class PartitionEntry(NamedTuple):
    name: str
    version: str
    base_address: int
    size: int
    type: PartitionType


@dataclass
class PartitionManifestEntry:
    name: str
    type: PartitionManifestTypeId
    load: Annotated[int | None, mm_fields.Field(load_default=None)]
    size: Annotated[int | None, mm_fields.Field(load_default=None)]
    version: Annotated[int | None, mm_fields.Field(load_default=None)]


@dataclass
class PartitionManifest:
    partitions: list[PartitionManifestEntry]


MmPartitionManifest = mm_class_schema(PartitionManifest)


def scan_partition(blk: BufferedReader) -> list[PartitionEntry]:
    result: list[PartitionEntry] = []
    offset = 0

    while True:
        blk.seek(offset)
        if len(blk.peek(1)) == 0:
            break

        probe_result: ProbeResultKernel | ProbeResultData | None
        try:
            probe_result = probe_image(blk, from_here=True)
        except ProbeError:
            probe_result = None
        print(probe_result)
        if isinstance(probe_result, ProbeResultKernel):
            parsed_trailer: ImageMetadataV1 | ImageMetadataV2

            trailer_seek_offset = offset + probe_result.trailer_offset
            blk.seek(trailer_seek_offset)
            if probe_result.trailer_format_version == 1:
                # TODO v1 kernel trailer uses a slightly different format than
                # v1 image metadata. We should take that into account.
                parsed_trailer = CsImageMetadataV1.parse_stream(blk)
            else:
                parsed_trailer = CsImageMetadataV2.parse_stream(blk)

            print(parsed_trailer)
            result.append(PartitionEntry(
                name=parsed_trailer.image_name,
                version=parsed_trailer.image_version,
                base_address=offset,
                size=parsed_trailer.data_size,
                type=PartitionType.KERNEL,
            ))

            offset += parsed_trailer.data_size
            continue
        elif isinstance(probe_result, ProbeResultData):
            parsed_header: ImageMetadataV1 | ImageMetadataV2
            data_type: PartitionType

            blk.seek(offset)
            if probe_result.header_format_version == 1:
                parsed_header = CsImageMetadataV1.parse_stream(blk)
                data_type = PartitionType.SYS_DATA
            else:
                parsed_header = CsImageMetadataV2.parse_stream(blk)
                data_type = PartitionType.APP_DATA if parsed_header.image_type_key == 0 else PartitionType.SYS_DATA

            result.append(PartitionEntry(
                name=parsed_header.image_name,
                version=parsed_header.image_version,
                base_address=offset,
                size=parsed_header.content_size,
                type=data_type,
            ))
            offset += parsed_header.content_size
            continue
        else:
            # TODO: we need a fast way of scanning user data partitions and
            # stuff, but the NAND to block layer over the user data partition
            # of for NAND-based devices can be a pain to deal with...
            break

    return result
