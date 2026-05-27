from pathlib import Path
import sys

import click

from .formats import (
    ImageFileV2,
    probe_image,
)


@click.group()
def app():
    pass


@app.command(name='verify')
@click.argument('image', type=click.Path(file_okay=True, readable=True))
def do_verify(image: str):
    # TODO: replace this with a proper dispatcher class
    with open(image, 'rb') as f:
        probe = probe_image(f)
    if probe.header_format_version != 2:
        raise NotImplementedError('V1 image type handling is currently not implemented.')
    if probe.index_type != 2:
        raise RuntimeError(f'Unexpected index type {probe.index_type}.')

    file = ImageFileV2.load(image)
    status = file.verify()
    if all(status):
        click.echo(f'Image file {file.path} has been successfully verified.')
    else:
        click.echo(f'Image file {file.path} CANNOT be verified.')
        click.echo(f'Block status: {' '.join('OK' if s else 'NG' for s in status)}')
        sys.exit(1)


@app.command(name='build')
@click.argument('manifest', type=click.Path(dir_okay=True, readable=True))
@click.option('-o', '--output', type=click.Path(file_okay=True, writable=True))
def do_build(manifest: str, output: str | None):
    image_obj = ImageFileV2.from_manifest(manifest)
    if output is not None:
        image_obj.build(output)
    else:
        click.echo('Manifest is valid but no output specified. Not generating image.')


@app.command(name='extract')
@click.argument('image', type=click.Path(file_okay=True, readable=True, path_type=Path))
@click.option('-o', '--output-dir', type=click.Path(writable=True, path_type=Path))
def do_extract(image: Path, output_dir: Path | None):
    image_obj = ImageFileV2.load(image)
    click.echo(f'Image loaded. Found {len(image_obj.index.entries)} objects.')
    if output_dir is None:
        output_dir = image.parent / image.stem
    image_obj.extract(output_dir)
    click.echo(f'Extracted {len(image_obj.index.entries)} objects under {output_dir}.')


@app.command(name='info')
@click.argument('image', type=click.Path(file_okay=True, readable=True, path_type=Path))
def do_info(image: Path):
    image_obj = ImageFileV2.load(image)
    assert image_obj.manifest is not None
    manifest = image_obj.manifest
    metadata = image_obj.metadata
    index = image_obj.index

    click.echo(f'Header Format Version: {manifest.header_format_version}')
    if manifest.header_format_version == 2:
        click.echo(f'V2 Index Format Version: 0x{manifest.index_format_version:08x}')
    click.echo(f'Image Name: {metadata.image_name}')
    click.echo(f'Type: {manifest.type} (0x{metadata.image_type_key:08x})')
    click.echo(f'Version: {metadata.image_version}')
    click.echo(f'Content Size: 0x{metadata.content_size:x}')
    click.echo(f'Data Size: 0x{metadata.data_size:x}')
    click.echo(f'Block Size: 0x{manifest.block_size:x}')
    click.echo(f'Checksum Block Size: 0x{metadata.checksum_block_size:x}')
    click.echo(f'Object Count: {len(index.entries)}')
    click.echo()
    click.echo('Objects:')
    for entry in index.entries:
        click.echo(f'  - Offset 0x{entry.offset:x} Size 0x{entry.size:x}')
