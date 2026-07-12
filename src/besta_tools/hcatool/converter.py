from collections.abc import Iterator
from io import BytesIO
from itertools import batched, chain
from pathlib import Path

from PIL import Image
from PIL.Image import Image as ImageType

from .formats import FrameType, Hca, HcaPalette4Bpp, PixelFormat
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

    outbuf = BytesIO()

    if hca.pixel_format == PixelFormat.P8:
        pal = hca.palette
        pal_rgb = pal.to_rgb()
        tc = hca.transparent_color_index
        for byte in byte_it:
            r, g, b = pal_rgb[byte]
            outbuf.write(bytes((
                round(r * 255),
                round(g * 255),
                round(b * 255),
                0 if tc == byte else 255,
            )))
    elif hca.pixel_format == PixelFormat.P4:
        pal = hca.palette
        assert isinstance(pal, HcaPalette4Bpp)
        color = pal.color
        tc = hca.transparent_color_index
        tc_available = 0 <= tc < 16
        tctc = ((tc << 4) | tc) & 0xff
        for byte in byte_it:
            cv = color[byte]
            if tc_available:
                is_tctc = tctc ^ byte
                is_tc0 = is_tctc & 0x0f == 0
                is_tc1 = is_tctc & 0xf0 == 0
            else:
                is_tc0 = False
                is_tc1 = False
            r0 = cv & 0xf
            g0 = (cv >> 4) & 0xf
            b0 = (cv >> 8) & 0xf
            r1 = (cv >> 12) & 0xf
            g1 = (cv >> 16) & 0xf
            b1 = (cv >> 20) & 0xf
            outbuf.write(bytes((
                (r0 << 4) | r0,
                (g0 << 4) | g0,
                (b0 << 4) | b0,
                0 if is_tc0 else 255,
                (r1 << 4) | r1,
                (g1 << 4) | g1,
                (b1 << 4) | b1,
                0 if is_tc1 else 255,
            )))
    elif hca.pixel_format == PixelFormat.RGB12:
        for twopixel in batched(byte_it, 3):
            r0 = twopixel[0] & 0xf
            g0 = (twopixel[0] >> 4) & 0xf
            b0 = (twopixel[1]) & 0xf
            r1 = (twopixel[1] >> 4) & 0xf
            g1 = (twopixel[2]) & 0xf
            b1 = (twopixel[2] >> 4) & 0xf

            outbuf.write(bytes((
                (r0 << 4) | r0,
                (g0 << 4) | g0,
                (b0 << 4) | b0,
                255,
                (r1 << 4) | r1,
                (g1 << 4) | g1,
                (b1 << 4) | b1,
                255,
            )))
    else:
        raise NotImplementedError()

    out = Image.frombuffer(
        'RGBA', (hca.width, hca.height), outbuf.getvalue(),
        'raw', 'RGBA', 0, 1
    )
    return out


# def dump_frames(hca: Hca, prefix: Path) -> None:
#     for i, frame in enumerate(hca.frames):
#         if frame.header.frame_type == FrameType.COMPRESSED:
            