from datetime import datetime

import pefile

from ..consts import EMPTY_DOS_HEADER, NT_HEADER, EMPTY_FILE_HEADER
from ..formats import ImageBuildContext
from ..utils import pefile_struct_calcsize, align


def complete_headers(context: ImageBuildContext):
    args = context['args']

    assert 'section_dicts' in context
    section_dicts = context['section_dicts']

    assert 'optional_header_dict' in context
    optional_header_dict = context['optional_header_dict']

    assert 'next_section_base' in context
    last_section_ends_at_vaddr = context['next_section_base']

    context['dos_header_dict'] = EMPTY_DOS_HEADER.copy()
    context['nt_header_dict'] = NT_HEADER.copy()

    file_header_dict = EMPTY_FILE_HEADER.copy()

    if not args.deterministic:
        file_header_dict['TimeDateStamp'] = int(datetime.now().timestamp())

    file_header_dict['Characteristics'] = (
        pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_EXECUTABLE_IMAGE'] |
            pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_32BIT_MACHINE'] |
            pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_DEBUG_STRIPPED']
    )
    if context['is_dll']:
        file_header_dict['Characteristics'] |= pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_DLL']
    file_header_dict['NumberOfSections'] = len(section_dicts)

    optional_header_size = (
        pefile_struct_calcsize(pefile.PE.__IMAGE_OPTIONAL_HEADER_format__) +
            pefile_struct_calcsize(pefile.PE.__IMAGE_DATA_DIRECTORY_format__) * pefile.IMAGE_NUMBEROF_DIRECTORY_ENTRIES
    )
    file_header_dict['SizeOfOptionalHeader'] = optional_header_size

    header_size = (
        pefile_struct_calcsize(pefile.PE.__IMAGE_DOS_HEADER_format__) +
            pefile_struct_calcsize(pefile.PE.__IMAGE_NT_HEADERS_format__) +
            pefile_struct_calcsize(pefile.PE.__IMAGE_FILE_HEADER_format__)
    )

    section_header_size = pefile_struct_calcsize(pefile.PE.__IMAGE_SECTION_HEADER_format__) * len(section_dicts)

    all_header_size = section_offset = align(header_size + optional_header_size + section_header_size, 0x200)
    optional_header_dict['SizeOfHeaders'] = all_header_size
    optional_header_dict['SizeOfImage'] = align(last_section_ends_at_vaddr, 0x1000)

    for section_dict in section_dicts:
        section_dict['PointerToRawData'] = section_offset
        section_offset += section_dict['SizeOfRawData']

    context['expected_image_size'] = section_offset

    context['file_header_dict'] = file_header_dict
