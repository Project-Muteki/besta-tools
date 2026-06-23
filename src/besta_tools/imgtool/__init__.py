from __future__ import annotations

from pathlib import Path
import sys

import click

from .formats import (
    ImageIndexEntryV1,
    ImageIndexV1,
    ImageMetadataV2,
    ProbeError,
    construct_from_image_file,
    construct_from_manifest,
)


@click.group(help='Tool for packing/unpacking Besta partition image files.')
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

    click.echo(f'Header Format Version: {manifest.header_format_version}')
    if manifest.header_format_version == 2:
        click.echo(f'V2 Index Format Version: 0x{manifest.index_format_version:08x}')
    click.echo(f'Image Name: {metadata.image_name}')
    if isinstance(metadata, ImageMetadataV2):
        click.echo(f'Type: {manifest.type} (0x{metadata.image_type_key:08x})')
    elif isinstance(index, ImageIndexV1):
        click.echo(f'Type: {manifest.type} (0x{index.image_type:08x})')
    click.echo(f'Version: {metadata.image_version}')
    click.echo(f'Content Size: 0x{metadata.content_size:x}')
    click.echo(f'Data Size: 0x{metadata.data_size:x}')
    click.echo(f'Block Size: 0x{manifest.block_size:x}')
    click.echo(f'Checksum Block Size: 0x{metadata.checksum_block_size:x}')
    click.echo(f'Object Count: {index.count_entries()}')
    click.echo()
    click.echo('Objects:')
    for entry in index.entries:
        if isinstance(entry, ImageIndexEntryV1) and entry.is_sentinel():
            break
        click.echo(f'  - Offset 0x{entry.offset:x} Size 0x{entry.size:x}')
