from collections.abc import Sequence
from enum import Enum, auto
from io import BufferedReader
import json
from pathlib import Path
from typing import Final

from PIL import Image
import click_extra as click
from click_extra import ColorOption, NoColorOption, TableFormat, VerbosityOption, VerboseOption, QuietOption, VersionOption, Style

from ..common.styling import ListLabel, label_field
from .converter import dump_all_hca_frames, frames_to_hca, hca_to_frames
from .formats import CsHca, PixelFormat


class CompressionOption(Enum):
    AUTO = auto()
    NO = auto()
    YES = auto()


# Preferred suffixes if they are not the same with the format name.
_IMAGE_SUFFIX_OVERRIDE: Final = {
    'JPEG': '.jpg',
    'JPEG2000': '.jp2',
    'SPIDER': '.spi',
}


# Exclude stub format from save format list.
# WMF is also excluded because it's platform-dependent.
_IMAGE_FORMAT_BLACKLIST: Final = frozenset((
    'BUFR',
    'GRIB',
    'HDF5',
    'WMF',
))


def rgb12_to_html(rgb12: int) -> str:
    r = rgb12 & 0xf
    g = (rgb12 >> 4) & 0xf
    b = (rgb12 >> 8) & 0xf
    return f'#{r:1x}{g:1x}{b:1x}'


def image_query_output_format() -> tuple[str, ...]:
    # This loads all builtin Pillow plugins and populates the SAVE dict.
    _ = Image.registered_extensions()
    return tuple(sorted(
        k for k in Image.SAVE.keys() if k not in _IMAGE_FORMAT_BLACKLIST
    ))


def jsonobj(v: str) -> dict[str, object]:
    return json.loads(v)  # pyright: ignore[reportAny]


def _get_suffix_from_pillow_type(type_: str | None) -> str:
    if type_ is None:
        return '.png'
    return _IMAGE_SUFFIX_OVERRIDE.get(type_, f'.{type_.lower()}')


@click.group(
    name='hcatool',
    help=(
        '''
        Parse and build Besta's High-Compressed Animation (HCA) files.

        This was the primary image format used by the Besta GUI subsystem,
        before they switched to PNGs and MP4/MJPEG on more powerful devices.
        It is however still the main image format used by the .book format,
        and is still being used in various occasions when simple animation
        with indexed color would suffice.

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
    click.secho(label_field(
        'Transparent Color Index',
        str(hca.transparent_color_index)
            if hca.allow_transparency
            else 'Not transparent'
    ))
    if hca.pixel_format != PixelFormat.RGB12:
        click.secho(
            label_field(
                'Skip Mark Present',
                ('No', 'Yes')[hca.allow_skip]
            )
        )
        color_table = tuple(
            (str(i), f'{Style(bold=True, fg=rgb12_to_html(c))(f'●')} {rgb12_to_html(c)}')
            for i, c in enumerate(hca.palette.to_rgb12())
        )
        click.secho('\n' + ListLabel('Palette Data') + ':')
        click.print_table(  # pyright: ignore[reportUnknownMemberType]
            color_table,
            ('#', 'Color'),
            table_format=TableFormat.ALIGNED,
        )

    frame_table = tuple(
        (str(i), str(frame.header.seq), frame.header.frame_type.name, str(len(frame.data)), str(frame.header.lpadding))
        for i, frame in enumerate(hca.frames)
    )

    click.secho('\n' + ListLabel('Frames') + ':')
    click.print_table(  # pyright: ignore[reportUnknownMemberType]
        frame_table,
        ('#', 'Seq#', 'Format', 'Size', 'L. Pad'),
        table_format=TableFormat.ALIGNED,
    )


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
        extra _e suffix.

        The transparency property overlay colors the pixels that need to be
        deleted from the canvas as red (#ff00007f) and pixels that need to be
        carried over from the canvas as green (#00ff007f). Opaque pixels are
        marked as white (#ffffff7f).

        Both output image types may have a dimension larger than the size
        indicated in the HCA header due to padding.

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


@app.command(
    'encode',
    short_help='Encode a HCA image from well-formatted series of images.',
    help=(
        '''
        Encode a HCA image from well-formatted series of IMAGES.

        This command will generally not attempt to coerce the input images into
        a compatible encoding, nor to do pre-processing. This means care has to
        be taken when exporting images for use with the encode command.
        Specifically, the input images must follow the following rules:

        1. If encoding an animation with more than one frame, the input images
        must use indexed color with less than 256 colors in P8 mode, or less
        than 16 colors in P4 mode. If --coalesce is specified, however, the
        images can have up to 256 and 16 colors respectively, at the cost of
        potentially larger output file size due to every frame being an
        I-frame. All colors in the palette will also be clipped to RGB12.

        2. All images must also use the exact same palette and have exactly the
        same width and height. A common mistake is to let the image authoring
        software to trim unused colors when exporting images. Make sure to
        include unused colors when doing so.

        3. If encoding a static image with --color-mode rgb12, the input
        image can be in RGB or RGBA format, but any transparency information
        will be lost, all colors will be clipped to RGB12, and the image
        width MUST be a multiple of 4. Due to this, passing arbitrary static
        images to the encode command is still discouraged, despite the
        hard restrictions around static HCA is more relaxed comparing to
        animated HCAs.
        '''
    )
)
@click.argument('hca', type=click.Path(dir_okay=False, writable=True, path_type=Path))
@click.argument('image', type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument('images', nargs=-1, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    '--coalesce/--no-coalesce',
    default=False,
    help='If specified, B-frame encoding will be disabled and each image will be outputted as-is to the HCA file.',
)
@click.option(
    '-m', '--color-mode',
    required=True,
    type=click.Choice(PixelFormat, case_sensitive=False),
    help='Color mode to use. Note that RGB12 is not supported if you supply more than one images.',
)
@click.option(
    '-c', '--compress',
    type=click.Choice(CompressionOption, case_sensitive=False),
    default=CompressionOption.AUTO,
    help='Whether compression should be performed on frames. If set to auto, compression will be used if it yields smaller file.',
)
def do_build(hca: Path, image: Path, images: Sequence[Path], coalesce: bool, color_mode: PixelFormat, compress: CompressionOption) -> None:
    COMP: dict[CompressionOption, bool | None] = {
        CompressionOption.AUTO: None,
        CompressionOption.NO: False,
        CompressionOption.YES: True,
    }

    images_ = (image, *images)

    frames = [Image.open(path) for path in images_]
    hca_obj = frames_to_hca(frames, color_mode, coalesce, COMP[compress])

    CsHca.build_file(hca_obj, hca)


@app.command(
    'decode',
    short_help='Decode a HCA image to a series of images.',
    help=(
        '''
        Decode a HCA image to a series of images.

        This is only guaranteed to be lossless when the input HCA has been
        encoded by the encode command (due to how the HCA palette works),
        and the output image format must support palette (when the HCA pixel
        format is P8 or P4).
        '''
    )
)
@click.argument('hca', type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    '-o', '--output',
    type=click.Path(path_type=Path),
    help='Override output file name. If not specified, the name of the original HCA file will be used.',
)
@click.option(
    '-f', '--format', 'format_',
    type=click.Choice(image_query_output_format(), case_sensitive=False),
    help='Image format of the output images. If unspecified, the format will be automatically inferred from suffix.',
)
@click.option(
    '--save-parameters',
    type=jsonobj,
    default='{}',
    help='JSON representation of any extra save parameters passed to Pillow. Note that not all options can be used.',
)
def do_decode(hca: Path, output: Path | None, format_: str | None, save_parameters: dict[str, object]) -> None:
    if 'format' in save_parameters:
        del save_parameters['format']

    hca_obj = CsHca.parse_file(hca)
    frames = hca_to_frames(hca_obj)
    if output is None:
        output = hca.with_suffix(_get_suffix_from_pillow_type(format_))
    if len(frames) == 1:
        frames[0].save(output, format_, **save_parameters)
    else:
        for i, frame in enumerate(frames):
            output_name = output.with_stem(f'{output.stem}_{i}')
            frame.save(output_name, format_, **save_parameters)
