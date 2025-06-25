import argparse
import io
import logging
import os
import shutil
from typing import BinaryIO, Callable

from elftools.elf.elffile import ELFFile

from .consts import BESTAPE_MAX_ROMSPEC_SIZE, BESTAPE_MAX_HEADER_SIZE
from .formats import ImageBuildContext
from .steps.serialize import serialize
from .utils import get_executable_segment

from .steps.initialize import initialize_directory_dicts, detect_type
from .steps.scan_segments import scan_segments
from .steps.generate_sections import generate_rsrc, generate_reloc
from .steps.complete_headers import complete_headers


logger = logging.getLogger('elf2bestape.cli')


STEPS: list[Callable[[ImageBuildContext], None]] = [
    initialize_directory_dicts,
    detect_type,
    scan_segments,
    generate_rsrc,
    generate_reloc,
    complete_headers,
    serialize,
]


def parse_loglevel(level: str) -> int | str:
    try:
        return int(level)
    except ValueError:
        return level


def parse_args() -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    p = argparse.ArgumentParser(description='Generate Besta PE file from an AAELF file.')
    p.add_argument('elf', help='Input AAELF file.')
    p.add_argument('-l', '--log-level', type=parse_loglevel, default='INFO', help='Set log level.')
    p.add_argument('-o', '--output',
                   help='Besta PE file to output (or AAELF\'s basename + .exe if not supplied).')
    p.add_argument('-r', '--romspec-file', help='Include binary ROM spec file to make Type 2 ROM file.')
    p.add_argument('--deterministic', action=argparse.BooleanOptionalAction, default=True,
                   help='Enable deterministic conversion. (i.e. populate the timestamp field with a hash value '
                        'measured from selected PE headers and all sections instead of the actual build timestamp)')
    return p, p.parse_args()


def convert(elf_file: BinaryIO, pe_file: io.BytesIO, romspec: bytes | None, args: argparse.Namespace):
    elf = ELFFile(elf_file)
    executable_seg = get_executable_segment(elf)
    elf_base = elf.get_segment(executable_seg)['p_vaddr']
    image_base = elf_base - BESTAPE_MAX_HEADER_SIZE

    context: ImageBuildContext = {
        'args': args,
        'elf': ELFFile(elf_file),
        'elf_base': elf_base,
        'image_base': image_base,
        'patches': {},
        'output': pe_file,
        'romspec': romspec,
        'is_dll': False,
    }

    for step in STEPS:
        step(context)


def main():
    _, args = parse_args()

    logging.basicConfig(level=args.log_level if args.log_level is not None else None)

    if args.output is None:
        output_path = f'{os.path.splitext(args.elf)[0]}{os.path.extsep}exe'
    else:
        output_path = args.output

    if args.romspec_file is not None:
        if os.stat(args.romspec_file).st_size > BESTAPE_MAX_ROMSPEC_SIZE:
            raise RuntimeError('Refusing to link ROM spec file of size greater than 32KiB.')
        with open(args.romspec_file, 'rb') as romspec_file:
            romspec = romspec_file.read()
    else:
        romspec = None

    with open(args.elf, 'rb') as elf_file:
        pe_file = io.BytesIO()
        convert(elf_file, pe_file, romspec, args)
    with open(output_path, 'wb') as actual_pe_file:
        pe_file.seek(0)
        shutil.copyfileobj(pe_file, actual_pe_file)
