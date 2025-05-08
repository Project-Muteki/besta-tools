# Generate sections that don't map to any ELF segment.
import io
import logging
from collections import defaultdict

import pefile
from elftools.elf.relocation import RelocationSection
from elftools.elf import constants as elfconsts

from ..consts import EMPTY_IMAGE_RESOURCE_DIRECTORY, IMAGE_RESOURCE_DIRECTORY_SIZE, \
    EMPTY_IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE, IMAGE_RESOURCE_DIRECTORY_ENTRY_ISDIR, \
    EMPTY_IMAGE_RESOURCE_DATA_ENTRY, IMAGE_RESOURCE_DATA_ENTRY_SIZE, RSRC_NAME_BIN, \
    IMAGE_RESOURCE_DIRECTORY_ENTRY_ISNAME, RSRC_NAME_ROMSPC, RSRC_NAME_NIL, EMPTY_SECTION_HEADER, AAELF_RELOC_ABSOLUTE, \
    R_ARM_PREL31, AAELF_RELOC_RELATIVE, AAELF_RELOC_IGNORE, ENUM_RELOC_NAME_ARM
from ..formats import ImageBuildContext, SectionLeaf
from ..utils import pefile_struct_from_dict, align
from ...common.utils import BinaryBuilder


logger = logging.getLogger('elf2bestape.steps.generate_sections')


def generate_rsrc(context: ImageBuildContext):
    """
    Generate .rsrc section when user specifies a ROM spec file.
    :param context:
    :return:
    """
    rsrc_data = None

    assert 'next_section_base' in context
    assert 'section_dicts' in context
    assert 'directory_dicts' in context

    rsrc_base = context['next_section_base']
    section_dicts = context['section_dicts']
    rsrc_directory = context['directory_dicts'][pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]

    if context['romspec'] is not None:
        romspec = context['romspec']

        # Generate rsrc data
        rsrc_emitter = BinaryBuilder()

        # /
        rsrc_root_dict = EMPTY_IMAGE_RESOURCE_DIRECTORY.copy()
        rsrc_root_fragment = rsrc_emitter.append(IMAGE_RESOURCE_DIRECTORY_SIZE)

        # /BIN
        rsrc_root_dict['NumberOfNamedEntries'] += 1
        rsrc_bin_entry_dict = EMPTY_IMAGE_RESOURCE_DIRECTORY_ENTRY.copy()
        rsrc_bin_entry_fragment = rsrc_emitter.append(IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE)

        rsrc_bin_dict = EMPTY_IMAGE_RESOURCE_DIRECTORY.copy()
        rsrc_bin_fragment = rsrc_emitter.append(IMAGE_RESOURCE_DIRECTORY_SIZE)
        rsrc_bin_entry_dict['OffsetToData'] = IMAGE_RESOURCE_DIRECTORY_ENTRY_ISDIR | rsrc_bin_fragment.offset

        # /BIN/ROMSPC
        rsrc_bin_dict['NumberOfNamedEntries'] += 1
        rsrc_bin_romspc_entry_dict = EMPTY_IMAGE_RESOURCE_DIRECTORY_ENTRY.copy()
        rsrc_bin_romspc_entry_fragment = rsrc_emitter.append(IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE)

        rsrc_bin_romspc_dict = EMPTY_IMAGE_RESOURCE_DIRECTORY.copy()
        rsrc_bin_romspc_fragment = rsrc_emitter.append(IMAGE_RESOURCE_DIRECTORY_SIZE)
        rsrc_bin_romspc_entry_dict['OffsetToData'] = IMAGE_RESOURCE_DIRECTORY_ENTRY_ISDIR | rsrc_bin_romspc_fragment.offset

        # /BIN/ROMSPC/0x0401
        rsrc_bin_romspc_dict['NumberOfIdEntries'] += 1
        rsrc_bin_romspc_0404_entry_dict = EMPTY_IMAGE_RESOURCE_DIRECTORY_ENTRY.copy()
        rsrc_bin_romspc_0404_entry_fragment = rsrc_emitter.append(IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE)

        rsrc_bin_romspc_0404_data_entry_dict = EMPTY_IMAGE_RESOURCE_DATA_ENTRY.copy()
        rsrc_bin_romspc_0404_data_entry_fragment = rsrc_emitter.append(IMAGE_RESOURCE_DATA_ENTRY_SIZE)
        rsrc_bin_romspc_0404_entry_dict['OffsetToData'] = rsrc_bin_romspc_0404_data_entry_fragment.offset

        # Set up IDs and names
        rsrc_name_bin_fragment = rsrc_emitter.append(len(RSRC_NAME_BIN))
        rsrc_name_bin_fragment.set_data(RSRC_NAME_BIN)
        rsrc_bin_entry_dict['Name'] = IMAGE_RESOURCE_DIRECTORY_ENTRY_ISNAME | rsrc_name_bin_fragment.offset

        rsrc_name_romspc_fragment = rsrc_emitter.append(len(RSRC_NAME_ROMSPC))
        rsrc_name_romspc_fragment.set_data(RSRC_NAME_ROMSPC)
        rsrc_bin_romspc_entry_dict['Name'] = IMAGE_RESOURCE_DIRECTORY_ENTRY_ISNAME | rsrc_name_romspc_fragment.offset

        _rsrc_name_nil_fragment = rsrc_emitter.append(len(RSRC_NAME_NIL))
        _rsrc_name_nil_fragment.set_data(RSRC_NAME_NIL)

        rsrc_bin_romspc_0404_entry_dict['Name'] = 0x0404

        rsrc_romspc_data_fragment = rsrc_emitter.append(len(romspec))
        rsrc_bin_romspc_0404_data_entry_dict['OffsetToData'] = rsrc_base + rsrc_romspc_data_fragment.offset
        rsrc_bin_romspc_0404_data_entry_dict['Size'] = rsrc_romspc_data_fragment.size

        # Serialize headers
        rsrc_root_fragment.set_data(pefile_struct_from_dict(
            pefile.PE.__IMAGE_RESOURCE_DIRECTORY_format__,
            rsrc_root_dict,
            file_offset=rsrc_base + rsrc_root_fragment.offset,
        ).__pack__())

        rsrc_bin_entry_fragment.set_data(pefile_struct_from_dict(
            pefile.PE.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__,
            rsrc_bin_entry_dict,
            file_offset=rsrc_base + rsrc_bin_entry_fragment.offset,
        ).__pack__())

        rsrc_bin_fragment.set_data(pefile_struct_from_dict(
            pefile.PE.__IMAGE_RESOURCE_DIRECTORY_format__,
            rsrc_bin_dict,
            file_offset=rsrc_base + rsrc_bin_fragment.offset,
        ).__pack__())

        rsrc_bin_romspc_entry_fragment.set_data(pefile_struct_from_dict(
            pefile.PE.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__,
            rsrc_bin_romspc_entry_dict,
            file_offset=rsrc_base + rsrc_bin_romspc_entry_fragment.offset,
        ).__pack__())

        rsrc_bin_romspc_fragment.set_data(pefile_struct_from_dict(
            pefile.PE.__IMAGE_RESOURCE_DIRECTORY_format__,
            rsrc_bin_romspc_dict,
            file_offset=rsrc_base + rsrc_bin_romspc_fragment.offset,
        ).__pack__())

        rsrc_bin_romspc_0404_entry_fragment.set_data(pefile_struct_from_dict(
            pefile.PE.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__,
            rsrc_bin_romspc_0404_entry_dict,
            file_offset=rsrc_base + rsrc_bin_romspc_0404_entry_fragment.offset,
        ).__pack__())

        rsrc_bin_romspc_0404_data_entry_fragment.set_data(pefile_struct_from_dict(
            pefile.PE.__IMAGE_RESOURCE_DATA_ENTRY_format__,
            rsrc_bin_romspc_0404_data_entry_dict,
            file_offset=rsrc_base + rsrc_bin_romspc_0404_data_entry_fragment.offset,
        ).__pack__())

        rsrc_romspc_data_fragment.set_data(romspec)

        rsrc_data = SectionLeaf(rsrc_emitter.concat(), 0, False)
        context['rsrc_data'] = rsrc_data

    if rsrc_data is not None:
        # Calculate rsrc allocation size
        rsrc_memsize = len(rsrc_data.data)
        rsrc_size = align(rsrc_memsize, 0x200)
        rsrc_vsize = align(rsrc_memsize, 0x1000)
        logger.debug('rsrc_memsize = %s, rsrc_vsize = %s', hex(rsrc_memsize), hex(rsrc_vsize))
    else:
        rsrc_memsize = rsrc_size = rsrc_vsize = 0

    if rsrc_data is not None:
        # Append rsrc header
        rsrc_section_header = EMPTY_SECTION_HEADER.copy()
        rsrc_section_header['Name'] = b'.rsrc'
        rsrc_section_header['Characteristics'] = (
            pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA'] |
                pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']
        )
        rsrc_section_header['Misc_VirtualSize'] = rsrc_section_header['Misc_PhysicalAddress'] = rsrc_section_header['Misc'] = rsrc_memsize
        rsrc_section_header['VirtualAddress'] = rsrc_base
        rsrc_section_header['SizeOfRawData'] = rsrc_size
        section_dicts.append(rsrc_section_header)
        rsrc_directory['VirtualAddress'] = rsrc_base
        rsrc_directory['Size'] = rsrc_memsize

    context['next_section_base'] = rsrc_base + rsrc_vsize


def generate_reloc(context: ImageBuildContext):
    """
    Traverse through the ELF .rel.* sections and generate a single PE .reloc section.
    :param context:
    :return:
    """
    elf = context['elf']
    elf_base = context['elf_base']
    image_base = context['image_base']

    assert 'section_dicts' in context
    section_dicts = context['section_dicts']

    assert 'next_section_base' in context
    reloc_base = context['next_section_base']

    assert 'directory_dicts' in context
    reloc_directory = context['directory_dicts'][pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']]

    reloc_dicts: dict[int, dict[int, int]] = defaultdict(dict)
    # Generate the reloc table
    for rel_section in elf.iter_sections():
        if isinstance(rel_section, RelocationSection):
            logger.debug('Processing section %s', rel_section.name)
            # Complain on RELA
            if rel_section.is_RELA():
                raise RuntimeError('RELA relocation is not supported.')

            rel_target_sec = elf.get_section(rel_section['sh_info'])
            # Skip non-loadable sections
            if (rel_target_sec['sh_flags'] & elfconsts.SH_FLAGS.SHF_ALLOC) == 0:
                continue
            rel_target_data = rel_target_sec.data()

            if rel_section.name in ('.rel.ARM.exidx', '.rel.ARM.extab', '.rel.eh_frame'):
                # exidx and extab are handled by libgcc's unwind routine. Do nothing here.
                logger.info('Skipping exception related section.')
                continue

            for reloc in rel_section.iter_relocations():
                symtab = elf.get_section(rel_section['sh_link'])
                sym, type_ = symtab.get_symbol(reloc['r_info_sym']), reloc['r_info_type']
                sym_offset = sym['st_value']
                rel_offset = reloc['r_offset']
                rel_word_offset = rel_offset - rel_target_sec['sh_addr']
                rel_target_word = int.from_bytes(rel_target_data[rel_word_offset:rel_word_offset+4], 'little')

                if rel_word_offset < 0 or rel_word_offset >= len(rel_target_data):
                    logger.info('Ignoring out of bound symbol @ %#x', rel_word_offset)
                    continue

                if type_ in AAELF_RELOC_ABSOLUTE:
                    logger.debug('Abs reloc type=%s, value=%#010x, sym_value=%#010x, @ %#010x (%#010x in section)', ENUM_RELOC_NAME_ARM[type_], rel_target_word, sym_offset, rel_offset, rel_word_offset)
                    if sym['st_info']['bind'] == 'STB_WEAK' and sym_offset == 0:
                        logger.debug('Skipping weak symbols.')
                        continue

                    assert rel_target_word >= elf_base, 'REL symbol is not a valid address within the program.'
                    rel_offset_hi = rel_offset & 0xfffff000
                    rel_offset_lo = rel_offset & 0x00000fff
                    reloc_dicts[rel_offset_hi][rel_offset_lo] = pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']

                elif type_ == R_ARM_PREL31:
                    logger.info('Ignoring non-exception PREL31 (%#010x @ %#010x).', rel_target_word, rel_offset)

                elif type_ in AAELF_RELOC_RELATIVE:
                    logger.info('Ignoring relative reloc (%#010x @ %#010x).', rel_target_word, rel_offset)

                elif type_ in AAELF_RELOC_IGNORE:
                    continue
                else:
                    raise RuntimeError(f'Unhandled reloc type {ENUM_RELOC_NAME_ARM[type_]}')

    # Actually generate relocs
    generated_relocs: list[pefile.Structure] = []
    reloc_pos = 0
    for hi, los in reloc_dicts.items():
        base_reloc_struct = pefile_struct_from_dict(
            pefile.PE.__IMAGE_BASE_RELOCATION_format__,
            {'VirtualAddress': hi - image_base, 'SizeOfBlock': 0},
            file_offset=reloc_pos
        )
        generated_relocs.append(base_reloc_struct)
        base_reloc_struct.SizeOfBlock = 8
        reloc_pos += generated_relocs[-1].sizeof()
        for lo, type_ in los.items():
            generated_relocs.append(pefile_struct_from_dict(
                pefile.PE.__IMAGE_BASE_RELOCATION_ENTRY_format__,
                {'Data': (type_ << 12 | lo)},
                file_offset=reloc_pos
            ))
            reloc_pos += generated_relocs[-1].sizeof()
            base_reloc_struct.SizeOfBlock += generated_relocs[-1].sizeof()
        if len(los) % 2 == 1:
            # pad the entry so the reloc table is always 4 byte aligned
            generated_relocs.append(pefile_struct_from_dict(
                pefile.PE.__IMAGE_BASE_RELOCATION_ENTRY_format__,
                {'Data': 0},
                file_offset=reloc_pos
            ))
            reloc_pos += generated_relocs[-1].sizeof()
            base_reloc_struct.SizeOfBlock += generated_relocs[-1].sizeof()

    relocs_data_io = io.BytesIO()
    for reloc_struct in generated_relocs:
        relocs_data_io.write(reloc_struct.__pack__())

    context['reloc_data'] = SectionLeaf(relocs_data_io.getvalue(), 0, True)
    reloc_size = align(reloc_pos, 0x200, greedy=True)
    reloc_memsize = reloc_pos

    reloc_section_header = EMPTY_SECTION_HEADER.copy()
    reloc_section_header['Name'] = b'.reloc'
    reloc_section_header['Characteristics'] = (
        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA'] |
            pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_DISCARDABLE'] |
            pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']
    )
    reloc_section_header['Misc_VirtualSize'] = reloc_section_header['Misc_PhysicalAddress'] = reloc_section_header['Misc'] = reloc_memsize
    reloc_section_header['VirtualAddress'] = reloc_base
    reloc_section_header['SizeOfRawData'] = reloc_size
    section_dicts.append(reloc_section_header)

    reloc_directory['VirtualAddress'] = reloc_base
    reloc_directory['Size'] = reloc_memsize

    context['next_section_base'] = reloc_base + reloc_memsize
