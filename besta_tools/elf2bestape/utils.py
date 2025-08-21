from typing import Sequence, Any

import pefile
from elftools.elf import constants as elfconsts


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

def align(pos: int, blksize: int, greedy: bool = False) -> int:
    return (pos // blksize * blksize) + (blksize if greedy or pos % blksize != 0 else 0)

def lalign(pos: int, blksize: int) -> int:
    return pos // blksize * blksize

def lpadding(pos: int, blksize: int) -> int:
    return pos - (pos // blksize * blksize)

def generate_padding(length: int, blksize: int, greedy: bool = False, pad_byte: int | None = None) -> bytes:
    pad_byte_b = bytearray(1)
    if pad_byte is not None:
        pad_byte_b[0] = pad_byte
    else:
        pad_byte_b[0] = 0
    return bytes(pad_byte_b) * (align(length, blksize, greedy=greedy) - length)

def get_executable_segment(elf):
    for idx, seg in enumerate(elf.iter_segments()):
        if seg['p_type'] == 'PT_LOAD' and seg['p_flags'] == (elfconsts.P_FLAGS.PF_R | elfconsts.P_FLAGS.PF_X):
            return idx
    raise RuntimeError('Cannot find executable segment.')
