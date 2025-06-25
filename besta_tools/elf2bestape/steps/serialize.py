import logging
import hashlib
from typing import Sequence, Literal

import pefile

from ..consts import PEFILE_WARNING_TOO_MANY_0
from ..formats import ImageBuildContext
from ..utils import pefile_struct_from_dict, generate_padding

logger = logging.getLogger('elf2bestape.steps.serialize')

SECTION_LEAVES: Sequence[Literal['text_data', 'rdata_data', 'data_data', 'rsrc_data', 'reloc_data']] = ('text_data', 'rdata_data', 'data_data', 'rsrc_data', 'reloc_data')

def serialize(context: ImageBuildContext):
    build_id_measurer = hashlib.sha256()

    pos = 0x0

    pe_file = context['output']
    args = context['args']

    assert 'text_data' in context
    #assert 'rdata_data' in context
    assert 'data_data' in context
    assert 'reloc_data' in context

    dos_header = pefile_struct_from_dict(
        pefile.PE.__IMAGE_DOS_HEADER_format__,
        context['dos_header_dict'],
        file_offset=pos
    )
    pos += dos_header.sizeof()

    nt_header = pefile_struct_from_dict(
        pefile.PE.__IMAGE_NT_HEADERS_format__,
        context['nt_header_dict'],
        file_offset=pos
    )
    pos += nt_header.sizeof()

    file_header = pefile_struct_from_dict(
        pefile.PE.__IMAGE_FILE_HEADER_format__,
        context['file_header_dict'],
        file_offset=pos
    )
    pos += file_header.sizeof()
    build_id_measurer.update(file_header.__pack__())

    optional_header = pefile_struct_from_dict(
        pefile.PE.__IMAGE_OPTIONAL_HEADER_format__,
        context['optional_header_dict'],
        file_offset=pos
    )
    pos += optional_header.sizeof()
    build_id_measurer.update(optional_header.__pack__())

    directories: list[pefile.Structure] = []
    for directory_dict in context['directory_dicts']:
        dir_ = pefile_struct_from_dict(pefile.PE.__IMAGE_DATA_DIRECTORY_format__, directory_dict, file_offset=pos)
        pos += dir_.sizeof()
        directories.append(dir_)
        build_id_measurer.update(dir_.__pack__())

    sections: list[pefile.Structure] = []
    for sec in context['section_dicts']:
        pestruct = pefile_struct_from_dict(pefile.PE.__IMAGE_SECTION_HEADER_format__, sec, file_offset=pos)
        sections.append(pestruct)
        pos += pestruct.sizeof()

    logger.debug("File Header:")
    logger.debug(file_header)
    logger.debug('Optional Header:')
    logger.debug(optional_header)
    logger.debug('Directory Header:')
    for dir_ in directories:
        logger.debug(dir_)
    logger.debug('Section Header:')
    for sec in sections:
        logger.debug(sec)

    all_headers = (
        dos_header,
        nt_header,
        file_header,
        optional_header,
        *directories,
        *sections,
    )

    for hdr in all_headers:
        pe_file.write(hdr.__pack__())

    pe_file.write(generate_padding(pe_file.tell(), 0x200))

    for data in (
            context.get('text_data'),
            context.get('rdata_data'),
            context.get('data_data'),
            context.get('rsrc_data'),
            context.get('reloc_data')
    ):
        if data is not None:
            build_id_measurer.update(data.data)
            if data.lpad != 0:
                pe_file.write(b'\x00' * data.lpad)
            pe_file.write(data[0])
            pe_file.write(generate_padding(pe_file.tell(), 0x200, greedy=data.greedy))
    actual_image_size = len(pe_file.getvalue())
    assert actual_image_size == context['expected_image_size'], \
        (f'Inconsistent generated image size vs calculated '
         f'(expecting {context['expected_image_size']:#x}, got {actual_image_size:#x}).')

    # using pefile for some fixing and linting
    pefile_obj = pefile.PE(data=pe_file.getvalue())
    pefile_obj.OPTIONAL_HEADER.CheckSum = pefile_obj.generate_checksum()
    if args.deterministic:
        build_id_long = build_id_measurer.digest()
        logger.debug('Measured build ID: %s', build_id_long.hex())
        pefile_obj.FILE_HEADER.TimeDateStamp = int.from_bytes(build_id_long[-4:], 'big')

    for offset, val in context['patches'].items():
        rva = offset - context['image_base']
        logger.debug('Postprocessing: patch %d bytes at %#010x (RVA %#010x)', len(val), offset, rva)
        pefile_obj.set_bytes_at_rva(rva, val)

    pe_file.truncate(0)
    pe_file.seek(0)

    logger.debug('pefile objdump:\n%s', pefile_obj.dump_info())
    for pefile_warning in pefile_obj.get_warnings():
        if context['segment_load_file_size'] < 0x8000 and PEFILE_WARNING_TOO_MANY_0.match(pefile_warning) is not None:
            logger.debug('suppressed pefile warning: %s', pefile_warning)
            continue
        logger.info('pefile warning: %s', pefile_warning)
    pe_file.write(pefile_obj.write())
