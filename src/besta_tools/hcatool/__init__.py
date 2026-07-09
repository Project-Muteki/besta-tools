import click_extra as click
from click_extra import ColorOption, NoColorOption, VerbosityOption, VerboseOption, QuietOption, VersionOption


@click.group(
    name='hcatool',
    help=(
        '''
        Parse and build Besta's Highly Compressed Animation (HCA) files.

        This was the primary image format used by the Besta GUI subsystem,
        before they switched to PNGs for more powerful devices later.
        It is however still used in many occasions for simple animations and
        illustrations in .ebook format.

        It is a format similar to GIF, but optimized for fast rendering on
        low-powered hardware.
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
