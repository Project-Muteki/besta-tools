from __future__ import annotations
from enum import StrEnum

from filetype.types import APPLICATION, ARCHIVE, AUDIO, DOCUMENT, FONT, IMAGE, VIDEO

from besta_tools.common.styling import ListLabel, label_field
from besta_tools.imgtool.filetype import FatX, Ini, Iso9660, PxBundle, UnitIni

from .._version import *

from pathlib import Path
import sys

import click_extra as click
from click_extra import ColorOption, NoColorOption, TableFormat, VerbosityOption, VerboseOption, QuietOption, VersionOption

from .formats import (
    ImageIndexEntryV1,
    ImageIndexV1,
    ImageMetadataV2,
    ProbeError,
    construct_from_image_file,
    construct_from_manifest,
)


class MimeTypeTag(StrEnum):
    APPLICATION = click.style('[APP]', fg='green', bold=True)
    ARCHIVE = click.style('[ARC]', fg='red', bold=True)
    AUDIO = click.style('[AUD]', fg='cyan', bold=True)
    CONFIG = click.style('[CFG]', fg='yellow')
    DATA = '[DAT]'
    DOCUMENT = '[DOC]'
    EMPTY = click.style('[NIL]', fg='bright_black')
    FILESYSTEM = click.style('[DSK]', fg='blue', bold=True)
    FONT = click.style('[FNT]', fg='magenta')
    IMAGE = click.style('[IMG]', fg='magenta', bold=True)
    VIDEO = click.style('[VID]', fg='magenta', bold=True)


MIME_TO_TAG = {
    'inode/x-empty': MimeTypeTag.EMPTY,
    Ini.MIME: MimeTypeTag.CONFIG,
    UnitIni.MIME: MimeTypeTag.CONFIG,
    PxBundle.MIME: MimeTypeTag.ARCHIVE,
    FatX.MIME: MimeTypeTag.FILESYSTEM,
    Iso9660.MIME: MimeTypeTag.FILESYSTEM,
    **{i.mime: MimeTypeTag.IMAGE for i in IMAGE},
    **{i.mime: MimeTypeTag.VIDEO for i in VIDEO},
    **{i.mime: MimeTypeTag.AUDIO for i in AUDIO},
    **{i.mime: MimeTypeTag.FONT for i in FONT},
    **{i.mime: MimeTypeTag.ARCHIVE for i in ARCHIVE},
    **{i.mime: MimeTypeTag.APPLICATION for i in APPLICATION},
    **{i.mime: MimeTypeTag.DOCUMENT for i in DOCUMENT},
}


del MIME_TO_TAG['application/octet-stream']
# TODO have our own PE matching routines maybe
MIME_TO_TAG['application/x-msdownload'] = MimeTypeTag.APPLICATION


@click.group(
    name='imgtool',
    help='Tool for packing/unpacking Besta partition image files.',
    params=[
        ColorOption(),
        NoColorOption(),
        VerbosityOption(),
        VerboseOption(),
        QuietOption(),
        VersionOption(),
    ],
)
def app():
    pass


@app.command(
    name='verify',
    short_help='Verify the IMAGE with the builtin checksum block.',
    help='Verify the IMAGE with the builtin checksum block.',
)
@click.argument(
    'image',
    type=click.Path(file_okay=True, readable=True, path_type=Path),
)
def do_verify(image: Path):
    try:
        image_obj = construct_from_image_file(image)
    except ProbeError as e:
        click.echo(str(e))
        sys.exit(1)

    status = image_obj.verify()
    if all(status):
        click.echo(f'Image file {image_obj.path} has been successfully verified.')
    else:
        click.echo(f'Image file {image_obj.path} CANNOT be verified.')
        click.echo(f'Block status: {' '.join('OK' if s else 'NG' for s in status)}')
        sys.exit(1)


@app.command(
    name='build',
    short_help='Build the image from a MANIFEST file.',
    help='Build the image from a MANIFEST file.',
)
@click.argument(
    'manifest',
    type=click.Path(dir_okay=True, readable=True, path_type=Path),
)
@click.option(
    '-o', '--output',
    type=click.Path(file_okay=True, writable=True, path_type=Path),
    help=(
        'Path to the output file. If not specified, only validate the ' +
        'input MANIFEST and do not build anything.'
    )
)
def do_build(manifest: Path, output: Path | None):
    image_obj = construct_from_manifest(manifest)
    if output is not None:
        image_obj.build(output)
    else:
        click.echo('Manifest is valid but no output specified. Not generating image.')


@app.command(
    name='extract',
    short_help='Extract an IMAGE file.',
    help='Extract an IMAGE file.',
)
@click.argument(
    'image',
    type=click.Path(file_okay=True, readable=True, path_type=Path),
)
@click.option(
    '-o', '--output-dir',
    type=click.Path(writable=True, path_type=Path),
    help=(
        'Path to the output directory (defaults to the IMAGE path without ' +
        'suffix i.e. system/BA101.DAT -> system/BA101).'
    ),
)
def do_extract(image: Path, output_dir: Path | None):
    try:
        image_obj = construct_from_image_file(image)
    except ProbeError as e:
        click.echo(str(e))
        sys.exit(1)

    click.echo(f'Image loaded. Found {image_obj.index.count_entries()} objects.')
    if output_dir is None:
        output_dir = image.parent / image.stem
    image_obj.extract(output_dir)
    click.echo(f'Extracted {image_obj.index.count_entries()} objects under {output_dir}.')


@app.command(
    name='info',
    short_help='Print details of an IMAGE file.',
    help='Print details of an IMAGE file.',
)
@click.argument(
    'image',
    type=click.Path(file_okay=True, readable=True, path_type=Path),
)
def do_info(image: Path):
    try:
        image_obj = construct_from_image_file(image)
    except ProbeError as e:
        click.echo(str(e))
        sys.exit(1)

    manifest = image_obj.manifest
    metadata = image_obj.metadata
    index = image_obj.index
    assert image_obj.guessed_mime is not None

    click.secho(label_field('File', str(image)))
    click.secho(label_field('Header Format Version', str(manifest.header_format_version)))
    if manifest.header_format_version == 2:
        click.secho(label_field('V2 Index Format Version', f'0x{manifest.index_format_version:08x}'))
    click.secho(label_field('Image Name', metadata.image_name))
    if isinstance(metadata, ImageMetadataV2):
        click.secho(label_field('Type', f'{manifest.type} (0x{metadata.image_type_key:08x})'))
    elif isinstance(index, ImageIndexV1):
        click.secho(label_field('Type', f'{manifest.type} (0x{index.image_type:08x})'))
    click.secho(label_field('Version', metadata.image_version))
    click.secho(label_field('Content Size', hex(metadata.content_size)))
    click.secho(label_field('Data Size', hex(metadata.data_size)))
    click.secho(label_field('Block Size', hex(manifest.block_size)))
    click.secho(label_field('Checksum Block Size', hex(metadata.checksum_block_size)))
    click.secho(label_field('Object Count', str(index.count_entries())))
    click.echo()
    click.secho(ListLabel('Objects:'))
    table_data: list[tuple[str, str, str, str]] = []
    for i, entry in enumerate(index.entries):
        if isinstance(entry, ImageIndexEntryV1) and entry.is_sentinel():
            break
        mime = image_obj.guessed_mime[i]
        table_data.append((hex(i), hex(entry.offset), hex(entry.size), f'{click.style(MIME_TO_TAG.get(mime, MimeTypeTag.DATA))} {mime}'))
    click.print_table(  # pyright: ignore[reportUnknownMemberType], kwargs is untyped
        table_data,
        headers=list[str](
            ListLabel(x) for x in ('#', 'Offset', 'Size', 'Guessed MIME Type')
        ),
        table_format=TableFormat.ALIGNED,
    )
