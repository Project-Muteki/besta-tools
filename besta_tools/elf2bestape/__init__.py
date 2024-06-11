#!/usr/bin/env python3
from __future__ import annotations

from typing import (
    Any,
    Tuple,
    Dict,
    Sequence,
    Optional,
    BinaryIO,
    List,
    Union,
)

from collections import defaultdict

import argparse
import datetime
import enum
import io
import logging
import os
import shutil

import pefile
from elftools.elf.elffile import ELFFile
from elftools.elf import constants as elfconsts
from elftools.elf import enums as elfenums
from elftools.elf.relocation import RelocationSection


ELF2BESTAPE_VERSION = (0, 2, 0)


logger = logging.getLogger('elf2bestape')

def parse_loglevel(level: str) -> Union[int, str]:
    try:
        return int(level)
    except ValueError:
        return level


PEStructureDefinition = Tuple[str, Sequence[str]]

def pefile_struct_from_dict(format_: PEStructureDefinition, data: Dict[str, Any], name: Optional[str] = None, file_offset: Optional[int] = None) -> pefile.Structure:
    pe_struct = pefile.Structure(format_, name, file_offset)
    pe_struct.__dict__.update(data)
    return pe_struct

ENUM_RELOC_NAME_ARM = {v: k for k, v in elfenums.ENUM_RELOC_TYPE_ARM.items()}

AAELF_RELOC_ABSOLUTE = tuple(elfenums.ENUM_RELOC_TYPE_ARM[n] for n in (
    'R_ARM_ABS32',
    'R_ARM_TARGET1',
))

R_ARM_PREL31 = elfenums.ENUM_RELOC_TYPE_ARM['R_ARM_PREL31']

AAELF_RELOC_RELATIVE = tuple(elfenums.ENUM_RELOC_TYPE_ARM[n] for n in (
    'R_ARM_REL32',
    'R_ARM_TARGET2',
))

AAELF_RELOC_IGNORE = tuple(elfenums.ENUM_RELOC_TYPE_ARM[n] for n in (
    'R_ARM_CALL', # Relative offset will still be correct if we don't shift anything
    'R_ARM_THM_CALL', # Same as above
    'R_ARM_JUMP24', # Same as R_ARM_CALL
    'R_ARM_V4BX', # just a marker for v4T BX and safe to ignore
    'R_ARM_NONE', # Doesn't seem to be useful in an executable image
    'R_ARM_TLS_LE32', # TODO is this really the right thing to do?
    'R_ARM_TLS_IE32', # PC relative offset and should be handled by GCC codegen
))

EMPTY_DOS_HEADER = {
    'e_magic': pefile.IMAGE_DOS_SIGNATURE,
    'e_cblp': 0x0,
    'e_cp': 0x0,
    'e_crlc': 0x0,
    'e_cparhdr': 0x0,
    'e_minalloc': 0x0,
    'e_maxalloc': 0x0,
    'e_ss': 0x0,
    'e_sp': 0x0,
    'e_csum': 0x0,
    'e_ip': 0x0,
    'e_cs': 0x0,
    'e_lfarlc': 0x0,
    'e_ovno': 0x0,
    'e_res': b'\x00\x00\x00\x00\x00\x00\x00\x00',
    'e_oemid': 0x0,
    'e_oeminfo': 0x0,
    'e_res2': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    'e_lfanew': 0x40,
}

NT_HEADER = { 'Signature': pefile.IMAGE_NT_SIGNATURE }

EMPTY_FILE_HEADER = {
    'Machine': pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM'], # see pefile.MACHINE_TYPE
    'NumberOfSections': 0,
    'TimeDateStamp': 0,
    'PointerToSymbolTable': 0x0,
    'NumberOfSymbols': 0x0,
    'SizeOfOptionalHeader': 0, # To be filled later.
    'Characteristics': 0, # see pefile.IMAGE_CHARACTERISTICS
}

EMPTY_OPTIONAL_HEADER = {
    "Magic": pefile.OPTIONAL_HEADER_MAGIC_PE,
    "MajorLinkerVersion": ELF2BESTAPE_VERSION[0],
    "MinorLinkerVersion": ELF2BESTAPE_VERSION[1],
    "SizeOfCode": 0,
    "SizeOfInitializedData": 0,
    "SizeOfUninitializedData": 0,
    "AddressOfEntryPoint": 0,
    "BaseOfCode": 0,
    "BaseOfData": 0,
    "ImageBase": 0,
    "SectionAlignment": 0x1000,
    "FileAlignment": 0x200,
    "MajorOperatingSystemVersion": 4, # NT 4.0 (?)
    "MinorOperatingSystemVersion": 0,
    "MajorImageVersion": 1,
    "MinorImageVersion": 0,
    "MajorSubsystemVersion": 4,
    "MinorSubsystemVersion": 0,
    "Reserved1": 0,
    "SizeOfImage": 0,
    "SizeOfHeaders": 0, # Calculate from adding all header sizes
    "CheckSum": 0,
    "Subsystem": pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_WINDOWS_CE_GUI'], # pefile.SUBSYSTEM_TYPE
    "DllCharacteristics": 0, # pefile.DLL_CHARACTERISTICS
    "SizeOfStackReserve": 1 * 1024 * 1024,
    "SizeOfStackCommit": 4096,
    "SizeOfHeapReserve": 1 * 1024 * 1024,
    "SizeOfHeapCommit": 4096,
    "LoaderFlags": 0,
    "NumberOfRvaAndSizes": pefile.IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
}

EMPTY_SECTION_HEADER = {
    "Name": b'',
    "Misc_VirtualSize": 0,
    "VirtualAddress": 0,
    "SizeOfRawData": 0,
    "PointerToRawData": 0,
    "PointerToRelocations": 0,
    "PointerToLinenumbers": 0,
    "NumberOfRelocations": 0,
    "NumberOfLinenumbers": 0,
    "Characteristics": 0, # pefile.SECTION_CHARACTERISTICS
}

BESTAPE_MAX_HEADER_SIZE = 0x1000 # 1 memory page


class BestaPESection(enum.IntEnum):
    SCN_TEXT = 0
    SCN_RDATA = 1
    SCN_DATA = 2
    SCN_RELOC = 3
    TOTAL = 4


def align(pos: int, blksize: int) -> int:
    return (pos // blksize * blksize) + (blksize if pos % blksize != 0 else 0)

def lalign(pos: int, blksize: int) -> int:
    return pos // blksize * blksize

def lpadding(pos: int, blksize: int) -> int:
    return pos - (pos // blksize * blksize)

def parse_args() -> Tuple[argparse.ArgumentParser, argparse.Namespace]:
    p = argparse.ArgumentParser(description='Generate Besta PE file from an AAELF file.')
    p.add_argument('elf', help='Input AAELF file.')
    p.add_argument('-l', '--log-level', type=parse_loglevel, default='INFO', help='Set log level.')
    p.add_argument('-o', '--output', help='Besta PE file to output (or AAELF\'s basename + .exe if not supplied).')
    p.add_argument('--deterministic', action='store_true', default=False, help='Enable deterministic conversion. (i.e. omitting fields that may affect the hash of the binary such as build timestamp)')
    p.add_argument('--force-flattern-rel', action='store_true', default=False, help='Force the conversion of all general relative relocations to absolute. For testing only and normally should not be used.')
    return p, p.parse_args()

def generate_padding(length: int, blksize: int) -> bytes:
    return b'\x00' * (align(length, blksize) - length)

def get_executable_segment(elf):
    for idx, seg in enumerate(elf.iter_segments()):
        if seg['p_type'] == 'PT_LOAD' and seg['p_flags'] == (elfconsts.P_FLAGS.PF_R | elfconsts.P_FLAGS.PF_X):
            return idx
    raise RuntimeError('Cannot find executable segment.')

def convert(elf_file: BinaryIO, pe_file: io.BytesIO, args: argparse.Namespace):
    elf = ELFFile(elf_file)

    # Pass 1: Setup basic PE header fields
    optional_header_dict = EMPTY_OPTIONAL_HEADER.copy()
    text_base = 0
    data_base = 0
    text_size = 0
    data_size = 0
    bss_size = 0
    reloc_base = 0
    text_data: Optional[Union[Tuple[bytes, int], bytes]] = None
    rdata_data: Optional[Union[Tuple[bytes, int], bytes]] = None
    data_data: Optional[Union[Tuple[bytes, int], bytes]] = None
    executable_seg = get_executable_segment(elf)
    elf_base = elf.get_segment(executable_seg)['p_vaddr']
    image_base = elf_base - BESTAPE_MAX_HEADER_SIZE

    patches: Dict[int, bytes] = {}

    # Generate section headers
    section_dicts = []
    segment_lpaddings = {}
    for idx, seg in enumerate(elf.iter_segments()):
        sec_header_dict = EMPTY_SECTION_HEADER.copy()
        # Workaround data alignment issue in stock GCC ldscript.
        lpad = lpadding(seg['p_vaddr'] - image_base, 0x1000)
        if seg['p_type'] == 'PT_LOAD':
            if seg['p_flags'] == elfconsts.P_FLAGS.PF_R | elfconsts.P_FLAGS.PF_X:
                logger.info('Found segment that maps to .text at segment #%d', idx)
                if text_data is not None:
                    raise RuntimeError('.text section already exists.')
                sec_header_dict['Name'] = b'.text'
                sec_header_dict['Characteristics'] = (
                    pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE'] |
                        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] |
                        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']
                )
                text_base = seg['p_vaddr'] - image_base
                text_size = align(seg['p_filesz'], 0x200)
                text_data = (seg.data(), lpad)
            elif seg['p_flags'] == elfconsts.P_FLAGS.PF_R:
                logger.info('Found segment that maps to .rdata at segment #%d', idx)
                if rdata_data is not None:
                    raise RuntimeError('.rdata section already exists.')
                sec_header_dict['Name'] = b'.rdata'
                sec_header_dict['Characteristics'] = (
                    pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA'] |
                        pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']
                )
                data_base = seg['p_vaddr'] - image_base
                data_size += align(seg['p_filesz'], 0x200)
                rdata_data = (seg.data(), lpad)
            elif seg['p_flags'] == elfconsts.P_FLAGS.PF_R | elfconsts.P_FLAGS.PF_W:
                logger.info('Found segment that maps to .data at segment #%d', idx)
                if data_data is not None:
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
                    sec_header_dict['Characteristics'] |= pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']
                data_data = (seg.data(), lpad)
                # PE relocation table begins after the end of all ELF segments.
                reloc_base = align(seg['p_vaddr'] + seg['p_memsz'] - image_base, 0x1000)
            else:
                raise RuntimeError(f'Unknown PT_LOAD segment {idx} with flag {seg["p_flags"]:#010x}')
        elif seg['p_type'] in ('PT_ARM_EXIDX', 'PT_TLS'):
            continue
        else:
            raise RuntimeError(f'Unknown segment {seg["p_type"]}')
        sec_header_dict['Misc_VirtualSize'] = sec_header_dict['Misc_PhysicalAddress'] = sec_header_dict['Misc'] = seg['p_memsz']
        sec_header_dict['VirtualAddress'] = lalign(seg['p_vaddr'] - image_base, 0x1000)
        sec_header_dict['SizeOfRawData'] = align(seg['p_filesz'] + lpad, 0x200)
        if lpad != 0:
            logger.warning(f'ELF segment {idx} not aligned with page boundary. Manually padding it. This will slightly increase the executable size.')
        # To be fixed in pass 2
        # sec_header_dict['PointerToRawData']
        section_dicts.append(sec_header_dict)

    optional_header_dict['SizeOfCode'] = text_size
    optional_header_dict['SizeOfInitializedData'] = data_size
    optional_header_dict['SizeOfUninitializedData'] = bss_size
    optional_header_dict['AddressOfEntryPoint'] = elf['e_entry'] - image_base
    optional_header_dict['BaseOfCode'] = text_base
    optional_header_dict['BaseOfData'] = data_base
    optional_header_dict['ImageBase'] = image_base
    optional_header_dict['SectionAlignment'] = 0x1000
    # To be fixed in pass 2
    #optional_header_dict['SizeOfImage']
    #optional_header_dict['SizeOfHeaders']

    reloc_dicts: Dict[int, Dict[int, int]] = defaultdict(dict)
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
                # exidx and extab are relocated by libgcc's unwind routine. Do nothing here.
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
                        continue

                    assert rel_target_word >= elf_base, 'REL symbol is not a valid address within the program.'
                    rel_offset_hi = rel_offset & 0xfffff000
                    rel_offset_lo = rel_offset & 0x00000fff
                    reloc_dicts[rel_offset_hi][rel_offset_lo] = pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']

                elif type_ == R_ARM_PREL31 and args.force_flattern_rel:
                    logger.warning('Flatterning non-exception PREL31. This is probably unnecessary and harmful.')
                    is_exidx_compact = bool(rel_target_word & 0x80000000)
                    if is_exidx_compact:
                        continue

                    rel_target_word &= 0x7fffffff
                    # sign extend
                    prel31_off_signext = ((rel_target_word | 0x80000000) if (rel_target_word & 0x40000000) else rel_target_word)
                    prel31_off = int.from_bytes(prel31_off_signext.to_bytes(4, 'little'), 'little', signed=True)
                    new_rel_target_word = rel_offset + prel31_off

                    logger.debug('PREL31 reloc type=%s, value=%#x (abs=%#010x), sym_value=%#010x, @ %#010x (%#010x in section)', ENUM_RELOC_NAME_ARM[type_], prel31_off, new_rel_target_word, sym_offset, rel_offset, rel_word_offset)
                    assert new_rel_target_word >= elf_base, 'REL symbol is not a valid address within the program.'
                    patches[rel_offset] = new_rel_target_word.to_bytes(4, 'little')

                    rel_offset_hi = rel_offset & 0xfffff000
                    rel_offset_lo = rel_offset & 0x00000fff
                    reloc_dicts[rel_offset_hi][rel_offset_lo] = pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']
                elif type_ == R_ARM_PREL31:
                    logger.info('Ignoring non-exception PREL31 (%#010x @ %#010x).', rel_target_word, rel_offset)

                elif type_ in AAELF_RELOC_RELATIVE and args.force_flattern_rel:
                    logger.warning('Flatterning relative reloc. This is probably unnecessary and harmful.')
                    rel_target_off = int.from_bytes(rel_target_word.to_bytes(4, 'little'), 'little', signed=True)
                    new_rel_target_word = rel_offset + rel_target_off

                    logger.debug('Rel reloc type=%s, value=%#x (abs=%#010x), sym_value=%#010x, @ %#010x (%#010x in section)', ENUM_RELOC_NAME_ARM[type_], rel_target_off, new_rel_target_word, sym_offset, rel_offset, rel_word_offset)
                    assert new_rel_target_word >= elf_base, 'REL symbol is not a valid address within the program.'
                    patches[rel_offset] = new_rel_target_word.to_bytes(4, 'little')

                    rel_offset_hi = rel_offset & 0xfffff000
                    rel_offset_lo = rel_offset & 0x00000fff
                    reloc_dicts[rel_offset_hi][rel_offset_lo] = pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']
                elif type_ in AAELF_RELOC_RELATIVE:
                    logger.info('Ignoring relative reloc (%#010x @ %#010x).', rel_target_word, rel_offset)

                elif type_ in AAELF_RELOC_IGNORE:
                    continue
                else:
                    raise RuntimeError(f'Unhandled reloc type {ENUM_RELOC_NAME_ARM[type_]}')

    # Actually generate relocs
    generated_relocs: List[pefile.Structure] = []
    reloc_pos = 0
    for hi, los in reloc_dicts.items():
        base_reloc_struct = pefile_struct_from_dict(pefile.PE.__IMAGE_BASE_RELOCATION_format__, {'VirtualAddress': hi - image_base, 'SizeOfBlock': 0}, file_offset=reloc_pos)
        generated_relocs.append(base_reloc_struct)
        base_reloc_struct.SizeOfBlock = 8
        reloc_pos += generated_relocs[-1].sizeof()
        for lo, type_ in los.items():
            generated_relocs.append(pefile_struct_from_dict(pefile.PE.__IMAGE_BASE_RELOCATION_ENTRY_format__, {'Data': (type_ << 12 | lo)}, file_offset=reloc_pos))
            reloc_pos += generated_relocs[-1].sizeof()
            base_reloc_struct.SizeOfBlock += generated_relocs[-1].sizeof()
        if len(los) % 2 == 1:
            # pad the entry so the reloc table is always 4 byte aligned
            generated_relocs.append(pefile_struct_from_dict(pefile.PE.__IMAGE_BASE_RELOCATION_ENTRY_format__, {'Data': 0}, file_offset=reloc_pos))
            reloc_pos += generated_relocs[-1].sizeof()
            base_reloc_struct.SizeOfBlock += generated_relocs[-1].sizeof()

    relocs_data_io = io.BytesIO()
    for reloc_struct in generated_relocs:
        relocs_data_io.write(reloc_struct.__pack__())

    reloc_data = (relocs_data_io.getvalue(), 0)
    reloc_size = align(reloc_pos, 0x200)
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

    pos = 0x0

    dos_header = pefile_struct_from_dict(pefile.PE.__IMAGE_DOS_HEADER_format__, EMPTY_DOS_HEADER, file_offset=pos)
    pos += dos_header.sizeof()

    nt_header = pefile_struct_from_dict(pefile.PE.__IMAGE_NT_HEADERS_format__, NT_HEADER, file_offset=pos)
    pos += nt_header.sizeof()

    file_header_dict = EMPTY_FILE_HEADER.copy()
    # Number of sections will be filled in later

    if not args.deterministic:
        file_header_dict['TimeDateStamp'] = int(datetime.datetime.now().timestamp())

    file_header_dict['Characteristics'] = (
        pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_EXECUTABLE_IMAGE'] |
            pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_32BIT_MACHINE'] |
            pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_LINE_NUMS_STRIPPED'] |
            pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_LOCAL_SYMS_STRIPPED'] |
            pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_DEBUG_STRIPPED']
    )
    file_header_dict['NumberOfSections'] = len(section_dicts)
    file_header = pefile_struct_from_dict(pefile.PE.__IMAGE_FILE_HEADER_format__, file_header_dict, file_offset=pos)
    pos += file_header.sizeof()

    optional_header = pefile_struct_from_dict(pefile.PE.__IMAGE_OPTIONAL_HEADER_format__, optional_header_dict, file_offset=pos)
    pos += optional_header.sizeof()

    directories: List[pefile.Structure] = []
    for _ in range(pefile.IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
        dir_ = pefile_struct_from_dict(pefile.PE.__IMAGE_DATA_DIRECTORY_format__, {'VirtualAddress': 0, 'Size': 0}, file_offset=pos)
        pos += dir_.sizeof()
        directories.append(dir_)

    directories[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']].VirtualAddress = reloc_base
    directories[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']].Size = reloc_memsize

    # Set optional header size
    file_header.SizeOfOptionalHeader = optional_header.sizeof() + sum(dir_.sizeof() for dir_ in directories)

    sections: List[pefile.Structure] = []

    for sec in section_dicts:
        pestruct = pefile_struct_from_dict(pefile.PE.__IMAGE_SECTION_HEADER_format__, sec, file_offset=pos)
        sections.append(pestruct)
        pos += pestruct.sizeof()

    pos = align(pos, 0x200)

    # Pass 2: fixing field values that were not yet available during pass 1 and prepare the actual section data
    header_size = pos
    optional_header.SizeOfHeaders = header_size

    for sec_struct in sections:
        sec_struct.PointerToRawData = pos
        pos += sec_struct.SizeOfRawData # pylint:disable=invalid-name

    image_size = pos
    optional_header.SizeOfImage = align(reloc_base + reloc_memsize, 0x1000)

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

    for data in (text_data, rdata_data, data_data, reloc_data):
        if data is not None:
            lpad = data[1]
            if lpad != 0:
                pe_file.write(b'\x00' * lpad)
            pe_file.write(data[0])
            pe_file.write(generate_padding(pe_file.tell(), 0x200))
    actual_image_size = len(pe_file.getvalue())
    assert actual_image_size == image_size, f'Inconsistent generated image size vs calculated (expecting {image_size:#x}, got {actual_image_size:#x}).'

    # Pass 3: using pefile for some fixing and linting
    pefile_obj = pefile.PE(data=pe_file.getvalue())
    pefile_obj.OPTIONAL_HEADER.CheckSum = pefile_obj.generate_checksum()

    for offset, val in patches.items():
        rva = offset - image_base
        logger.debug('Postprocessing: patch %d bytes at %#010x (RVA %#010x)', len(val), offset, rva)
        pefile_obj.set_bytes_at_rva(rva, val)

    pe_file.truncate(0)
    pe_file.seek(0)

    logger.debug('pefile objdump:\n%s', pefile_obj.dump_info())
    for pefile_warning in pefile_obj.get_warnings():
        logger.info('pefile warning: %s', pefile_warning)
    pe_file.write(pefile_obj.write())

def main():
    _, args = parse_args()

    logging.basicConfig()
    if args.log_level is not None:
        logger.setLevel(args.log_level)

    if args.output is None:
        output_path = f'{os.path.splitext(args.elf)[0]}{os.path.extsep}exe'
    else:
        output_path = args.output
    with open(args.elf, 'rb') as elf_file:
        pe_file = io.BytesIO()
        convert(elf_file, pe_file, args)
    with open(output_path, 'wb') as actual_pe_file:
        pe_file.seek(0)
        shutil.copyfileobj(pe_file, actual_pe_file)

if __name__ == '__main__':
    main()
