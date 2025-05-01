# Scan ELF segments and generate metadata for them.

import logging

import pefile

from elftools.elf import constants as elfconsts

from ..utils import lpadding, align, lalign
from ..formats import ImageBuildContext, SectionLeaf
from ..consts import EMPTY_SECTION_HEADER, EMPTY_OPTIONAL_HEADER

logger = logging.getLogger('elf2bestape.steps.scan_segments')

def scan_segments(context: ImageBuildContext):
    elf = context['elf']
    image_base = context['image_base']

    text_size = 0
    text_base = 0
    data_base = 0
    data_size = 0
    bss_size = 0

    # Generate section headers
    section_dicts = []
    segment_load_file_size = 0
    for idx, seg in enumerate(elf.iter_segments()):
        sec_header_dict = EMPTY_SECTION_HEADER.copy()
        # Workaround data alignment issue in stock GCC ldscript.
        lpad = lpadding(seg['p_vaddr'] - image_base, 0x1000)
        if seg['p_type'] == 'PT_LOAD':
            if seg['p_flags'] == elfconsts.P_FLAGS.PF_R | elfconsts.P_FLAGS.PF_X:
                logger.info('Found segment that maps to .text at segment #%d', idx)
                if context.get('text_data') is not None:
                    raise RuntimeError('.text section already exists.')
                sec_header_dict['Name'] = b'.text'
                sec_header_dict['Characteristics'] = (
                    pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE'] |
                        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] |
                        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']
                )
                text_base = seg['p_vaddr'] - image_base
                text_size = align(seg['p_filesz'], 0x200)
                context['text_data'] = SectionLeaf(seg.data(), lpad, False)
            elif seg['p_flags'] == elfconsts.P_FLAGS.PF_R:
                logger.info('Found segment that maps to .rdata at segment #%d', idx)
                if context.get('rdata_data') is not None:
                    raise RuntimeError('.rdata section already exists.')
                sec_header_dict['Name'] = b'.rdata'
                sec_header_dict['Characteristics'] = (
                    pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA'] |
                        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']
                )
                data_base = seg['p_vaddr'] - image_base
                data_size += align(seg['p_filesz'], 0x200)
                context['rdata_data'] = SectionLeaf(seg.data(), lpad, False)
            elif seg['p_flags'] == elfconsts.P_FLAGS.PF_R | elfconsts.P_FLAGS.PF_W:
                logger.info('Found segment that maps to .data at segment #%d', idx)
                if context.get('data_data') is not None:
                    raise RuntimeError('.data section already exists.')
                sec_header_dict['Name'] = b'.data'
                sec_header_dict['Characteristics'] = (
                    pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA'] |
                        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] |
                        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']
                )
                data_size += align(seg['p_filesz'], 0x200)
                bss_size = seg['p_memsz'] - seg['p_filesz']
                if bss_size != 0:
                    sec_header_dict['Characteristics'] |= (
                        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA'])
                context['data_data'] = SectionLeaf(seg.data(), lpad, False)
                # PE generated sections begin after the end of all ELF segments.
                context['next_section_base'] = align(seg['p_vaddr'] + seg['p_memsz'] - image_base, 0x1000)
            else:
                raise RuntimeError(f'Unknown PT_LOAD segment {idx} with flag {seg["p_flags"]:#010x}')
            segment_load_file_size += seg['p_filesz']
        elif seg['p_type'] in ('PT_ARM_EXIDX', 'PT_TLS'):
            continue
        else:
            raise RuntimeError(f'Unknown segment {seg["p_type"]}')
        sec_header_dict['Misc_VirtualSize'] = sec_header_dict['Misc_PhysicalAddress'] = sec_header_dict['Misc'] = seg['p_memsz']
        sec_header_dict['VirtualAddress'] = lalign(seg['p_vaddr'] - image_base, 0x1000)
        sec_header_dict['SizeOfRawData'] = align(seg['p_filesz'] + lpad, 0x200)
        if lpad != 0:
            logger.warning(
                'ELF segment %d not aligned with page boundary. '
                'Manually padding it. This will slightly increase the executable size. '
                'Please consider rebuilding the file with the appropriate page size.', idx)
        # To be fixed in pass 2
        # sec_header_dict['PointerToRawData']
        section_dicts.append(sec_header_dict)

    optional_header_dict = EMPTY_OPTIONAL_HEADER.copy()
    optional_header_dict['SizeOfCode'] = text_size
    optional_header_dict['SizeOfInitializedData'] = data_size
    optional_header_dict['SizeOfUninitializedData'] = bss_size
    optional_header_dict['AddressOfEntryPoint'] = elf['e_entry'] - image_base
    optional_header_dict['BaseOfCode'] = text_base
    optional_header_dict['BaseOfData'] = data_base
    optional_header_dict['ImageBase'] = image_base
    optional_header_dict['SectionAlignment'] = 0x1000

    context['optional_header_dict'] = optional_header_dict
    context['section_dicts'] = section_dicts
    context['segment_load_file_size'] = segment_load_file_size
