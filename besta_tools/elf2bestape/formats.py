from typing import TypedDict, NamedTuple, TYPE_CHECKING, NotRequired, Any

if TYPE_CHECKING:
    import argparse
    import io
    from elftools.elf.elffile import ELFFile


class SectionLeaf(NamedTuple):
    data: bytes
    lpad: int
    greedy: bool


class ImageBuildContext(TypedDict):
    args: 'argparse.Namespace'
    elf: 'ELFFile'
    elf_base: int
    image_base: int
    patches: dict[int, bytes]
    romspec: bytes | None
    output: 'io.BytesIO'
    is_dll: bool
    next_section_base: NotRequired[int]
    expected_image_size: NotRequired[int]

    dos_header_dict: NotRequired[dict[Any, Any]]
    nt_header_dict: NotRequired[dict[Any, Any]]
    file_header_dict: NotRequired[dict[Any, Any]]
    optional_header_dict: NotRequired[dict[Any, Any]]
    section_dicts: NotRequired[list[dict[Any, Any]]]
    directory_dicts: NotRequired[list[dict[Any, Any]]]

    text_data: NotRequired[SectionLeaf]
    rdata_data: NotRequired[SectionLeaf]
    data_data: NotRequired[SectionLeaf]
    rsrc_data: NotRequired[SectionLeaf]
    reloc_data: NotRequired[SectionLeaf]

    segment_load_file_size: NotRequired[int]
