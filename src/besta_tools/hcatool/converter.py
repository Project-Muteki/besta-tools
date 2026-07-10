from collections.abc import Iterator
from io import BytesIO
from itertools import chain
from pathlib import Path

from PIL import Image
from PIL.Image import Image as ImageType

from .formats import FrameType, Hca, PixelFormat
from .lzw import BitstreamReader


def dump_hca_frame(hca: Hca, frame_index: int = 0) -> ImageType:
    if frame_index >= hca.nframes:
        raise ValueError(f'Frame {frame_index} does not exist.')

    byte_it: Iterator[int]
    frame = hca.frames[frame_index]
    if frame.header.frame_type == FrameType.COMPRESSED:
        byte_it = chain.from_iterable(BitstreamReader(BytesIO(frame.data)).decode())
    else:
        byte_it = iter(frame.data)

    out = Image.new('RGBA', (hca.width, hca.height))

    if hca.pixel_format == PixelFormat.P8:
        pal = hca.palette
        pal_rgb = pal.to_rgb()
        tc = hca.transparent_color_index
        w = hca.width
        for i, byte in enumerate(byte_it):
            r, g, b = pal_rgb[byte]
            out.putpixel(
                (i % w, i // w),
                (
                    round(r * 255),
                    round(g * 255),
                    round(b * 255),
                    0 if tc == byte else 255
                )
            )
    else:
        raise NotImplementedError()
    return out


# def dump_frames(hca: Hca, prefix: Path) -> None:
#     for i, frame in enumerate(hca.frames):
#         if frame.header.frame_type == FrameType.COMPRESSED:
            