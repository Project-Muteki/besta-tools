import enum
import re

import pefile
from elftools.elf import enums as elfenums

from .utils import pefile_struct_calcsize

PEFILE_WARNING_TOO_MANY_0 = re.compile(
    r"Byte 0x00 makes up [0-9]{2}\.?[0-9]+% of the file's contents. "
    r"This may indicate truncation / malformation."
)

ELF2BESTAPE_VERSION = (2, 0, 0)

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

EMPTY_IMAGE_RESOURCE_DIRECTORY = {
    'Characteristics': 0,
    'TimeDateStamp': 0,
    'MajorVersion': 0,
    'MinorVersion': 0,
    'NumberOfNamedEntries': 0,
    'NumberOfIdEntries': 0,
}

EMPTY_IMAGE_RESOURCE_DIRECTORY_ENTRY = {
    'Name': 0x0,
    'OffsetToData': 0x0,
}

EMPTY_IMAGE_RESOURCE_DATA_ENTRY = {
    'OffsetToData': 0x0,
    'Size': 0x0,
    'CodePage': 0x0,
    'Reserved': 0x0,
}

IMAGE_RESOURCE_DIRECTORY_SIZE = pefile_struct_calcsize(pefile.PE.__IMAGE_RESOURCE_DIRECTORY_format__)
IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE = pefile_struct_calcsize(pefile.PE.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__)
IMAGE_RESOURCE_DATA_ENTRY_SIZE = pefile_struct_calcsize(pefile.PE.__IMAGE_RESOURCE_DATA_ENTRY_format__)

RSRC_STR_BIN = 'BIN'
RSRC_STR_ROMSPC = 'ROMSPC'
RSRC_NAME_BIN = len(RSRC_STR_BIN).to_bytes(2, 'little') + RSRC_STR_BIN.encode('utf-16le')
RSRC_NAME_ROMSPC = len(RSRC_STR_ROMSPC).to_bytes(2, 'little') + RSRC_STR_ROMSPC.encode('utf-16le')
RSRC_NAME_NIL = (0).to_bytes(2, 'little')

IMAGE_RESOURCE_DIRECTORY_ENTRY_ISDIR = IMAGE_RESOURCE_DIRECTORY_ENTRY_ISNAME = 0x80000000

BESTAPE_MAX_HEADER_SIZE = 0x1000 # 1 memory page
BESTAPE_MAX_ROMSPEC_SIZE = 0x8000 # 8 memory page or 32KiB


class BestaPESection(enum.IntEnum):
    SCN_TEXT = 0
    SCN_RDATA = 1
    SCN_DATA = 2
    SCN_RELOC = 3
    TOTAL = 4
