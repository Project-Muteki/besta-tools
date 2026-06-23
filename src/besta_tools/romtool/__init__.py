from typing import BinaryIO

import tomllib

import click

from besta_tools.romtool.builder import build_embeddable_from_spec_file


@click.group(
    help='Tool for working with ROM files.',
)
def app():
    pass

@app.command(
    name='build',
    short_help='Build ROM from a SPEC-FILE',
    help='Build ROM from a SPEC-FILE',
)
@click.argument('spec-file', type=click.File('rb'))
@click.option(
    '-o', '--output',
    type=click.File('wb'),
    required=True,
    help='Path to the resulting ROM file.',
)
def do_build(spec_file: BinaryIO, output: BinaryIO):
    spec_dict = tomllib.load(spec_file)
    spec_built = build_embeddable_from_spec_file(spec_dict)
    output.write(spec_built)
