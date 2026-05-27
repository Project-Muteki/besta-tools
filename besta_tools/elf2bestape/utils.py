from typing import Sequence, Any

import pefile
from elftools.elf import constants as elfconsts

# These may look unused but they are re-exports
from ..common.utils import align, generate_padding


PEStructureDefinition = tuple[str, Sequence[str]]


def pefile_struct_calcsize(format_: PEStructureDefinition) -> int:
    pe_struct = pefile.Structure(format_)
    return pe_struct.sizeof()


def pefile_struct_from_dict(format_: PEStructureDefinition,
                            data: dict[str, Any], name: str | None = None,
                            file_offset: int | None = None) -> pefile.Structure:
    pe_struct = pefile.Structure(format_, name, file_offset)
    pe_struct.__dict__.update(data)
    return pe_struct

def lalign(pos: int, blksize: int) -> int:
    return pos // blksize * blksize

def lpadding(pos: int, blksize: int) -> int:
    return pos - (pos // blksize * blksize)

def get_executable_segment(elf):
    for idx, seg in enumerate(elf.iter_segments()):
        if seg['p_type'] == 'PT_LOAD' and seg['p_flags'] == (elfconsts.P_FLAGS.PF_R | elfconsts.P_FLAGS.PF_X):
            return idx
    raise RuntimeError('Cannot find executable segment.')
