from pathlib import Path

from .._version import *

import io
import logging
import shutil
from typing import BinaryIO, Callable

import click_extra as click
from click_extra import ColorOption, NoColorOption, VerbosityOption, VerboseOption, QuietOption, VersionOption
from click_extra import LogLevel

from elftools.elf.elffile import ELFFile

from .consts import BESTAPE_MAX_ROMSPEC_SIZE, BESTAPE_MAX_HEADER_SIZE
from .formats import ImageBuildContext, ExtraOptions
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


def convert(elf_file: BinaryIO, pe_file: io.BytesIO, romspec: bytes | None, args: ExtraOptions):
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


@click.command(
    name='elf2bestape',
    help='Generate Besta PE file from an AAELF file (ELF).',
    params=[
        ColorOption(),
        NoColorOption(),
        VerbosityOption(
            # Old cli d -l/--log-level and defaulted the level to INFO.
            # Replicate the behavior here.
            param_decls=['-l', '--log-level'],
            default=LogLevel.INFO,
        ),
        VerboseOption(),
        QuietOption(),
        VersionOption(),
    ],
)
@click.argument(
    'elf',
    type=click.Path(file_okay=True, readable=True, path_type=Path),
)
@click.option(
    '-o', '--output',
    type=click.Path(writable=True, path_type=Path),
    default=None,
    help='Besta PE file to output (or AAELF\'s basename + .exe if not supplied).',
)
@click.option(
    '-r', '--romspec-file',
    type=click.Path(file_okay=True, readable=True, path_type=Path),
    default=None,
    help='Include binary ROM spec file to make Type 2 ROM file.',
)
@click.option(
    '--deterministic/--no-deterministic',
    default=True,
    help=(
        'Enable deterministic conversion. (i.e. populate the timestamp ' +
        'field with a hash value measured from selected PE headers and ' +
        'all sections instead of the actual build timestamp)'
    ),
)
def app(elf: Path, output: Path | None, romspec_file: Path | None, deterministic: bool) -> None:
    if output is None:
        output = elf.with_suffix('.exe')

    if romspec_file is not None:
        if romspec_file.stat().st_size > BESTAPE_MAX_ROMSPEC_SIZE:
            raise RuntimeError('Refusing to link ROM spec file of size greater than 32KiB.')
        with romspec_file.open('rb') as romspec_file_:
            romspec = romspec_file_.read()
    else:
        romspec = None

    with elf.open('rb') as elf_file:
        pe_file = io.BytesIO()
        convert(elf_file, pe_file, romspec, ExtraOptions(deterministic=deterministic))
    with output.open('wb') as actual_pe_file:
        pe_file.seek(0)
        shutil.copyfileobj(pe_file, actual_pe_file)
