from io import BufferedReader
from pathlib import Path

import click_extra as click
from click_extra import ColorOption, NoColorOption, TableFormat, VerbosityOption, VerboseOption, QuietOption, VersionOption, Style

from besta_tools.common.styling import ListLabel, label_field
from besta_tools.hcatool.converter import dump_all_hca_frames
from besta_tools.hcatool.formats import CsHca, PixelFormat


def rgb12_to_html(rgb12: int) -> str:
    r = rgb12 & 0xf
    g = (rgb12 >> 4) & 0xf
    b = (rgb12 >> 8) & 0xf
    return f'#{r:1x}{g:1x}{b:1x}'


@click.group(
    name='hcatool',
    help=(
        '''
        Parse and build Besta's High-Compressed Animation (HCA) files.

        This was the primary image format used by the Besta GUI subsystem,
        before they switched to PNGs for more powerful devices later.
        It is however still used in many occasions for simple animations,
        illustrations in .ebook format, etc.

        The format is possibly inspired by GIF, but optimized for fast
        rendering on low-powered hardware rather than size and flexibility.
        '''
    ),
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
    'info',
    short_help='Print information of a HCA file',
    help='Print information of a HCA FILE.',
)
@click.argument(
    'file',
    type=click.File('rb'),
)
def do_info(file: BufferedReader) -> None:
    hca = CsHca.parse_stream(file)
    click.secho(label_field('File', str(file.name)))
    click.secho(label_field('Format', 'application/vnd.besta.hca'))
    click.secho(label_field('Pixel Format', hca.pixel_format.name))
    click.secho(label_field('Width', str(hca.width)))
    click.secho(label_field('Height', str(hca.height)))
    click.secho(label_field('Pitch', str(hca.pitch)))
    click.secho(label_field('# of Frames', str(hca.nframes)))
    click.secho(label_field('# of Colors', str(hca.palette_size)))
    allow_transparency = hca.transparent_color_index != 0xff
    click.secho(label_field(
        'Transparent Color Index',
        str(hca.transparent_color_index)
            if allow_transparency
            else 'Not transparent'
    ))
    if hca.pixel_format != PixelFormat.RGB12:
        click.secho(
            label_field(
                'Enabled B-frame Code',
                'Skip' if not allow_transparency else 'Skip+Erase'
            )
        )
        color_table = tuple(
            (str(i), f'{Style(bold=True, fg=rgb12_to_html(c))(f'●')} {rgb12_to_html(c)}')
            for i, c in enumerate(hca.palette.to_rgb12())
        )
        click.secho('\n' + ListLabel('Palette Data') + ':')
        click.print_table(color_table, ('#', 'Color'), table_format=TableFormat.ALIGNED)

    frame_table = tuple(
        (str(i), str(frame.header.seq), frame.header.frame_type.name, str(len(frame.data)), str(frame.header.lpadding))
        for i, frame in enumerate(hca.frames)
    )

    click.secho('\n' + ListLabel('Frames') + ':')
    click.print_table(frame_table, ('#', 'Seq#', 'Format', 'Size', 'L. Pad'), table_format=TableFormat.ALIGNED)


@app.command(
    'dump',
    short_help='Dump all frames of a HCA file.',
    help=(
        '''
        Dump all frames of a HCA FILE.

        Apply palette on all HCA frames and generate a series of PNG files in
        RGBA color format, and a series of transparency property overlay images
        if applicable. This does full palette lookup and correctly handles dual
        color instead of making approximations using only half of the palette.
        As a result, color index information of the original HCA file will be
        discarded.

        The image files will be named as the prefix specified with
        -p/--output-prefix, plus _idxMMM_seqNNN.png, where MMM is the frame
        index and NNN is the frame sequence number recorded in the HCA file.
        The transparency property overlays will be named similarly but with an
        extra _e.

        The transparecy property overlay colors the pixels that need to be
        deleted from the canvas as red (#ff00007f) and pixels that need to be
        carried over from the canvas as green (#00ff007f).

        Both image types may be larger than the size encoded in the metadata
        due to format design.

        This is more useful as a debugging tool and a HCA file inspector rather
        than as a general image manipulation pass.
        '''
    )
)
@click.argument(
    'file',
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    '-p', '--output-prefix',
    help='Prefix of outputs. If unspecified, this will be the FILE path without suffix.',
    type=click.Path(exists=False, writable=True, path_type=Path),
    default=None,
)
def do_dump(file: Path, output_prefix: Path | None) -> None:
    if output_prefix is None:
        output_prefix = Path(file.parent / file.stem)
    hca = CsHca.parse_file(file)
    dump_all_hca_frames(hca, output_prefix)
