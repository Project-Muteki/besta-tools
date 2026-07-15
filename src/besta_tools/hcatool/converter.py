from collections.abc import Iterator
from io import BytesIO
from itertools import batched, chain, repeat
from pathlib import Path

from PIL import Image
from PIL.Image import Image as ImageType

from .formats import FrameType, Hca, HcaFrameContainer, HcaPalette4Bpp, HcaPalette8Bpp, PixelFormat
from .lzw import BitstreamReader


def dump_hca_frame(hca: Hca, frame_index: int = 0, frame: HcaFrameContainer | None = None) -> tuple[ImageType | None, ImageType | None]:
    '''
    Apply palette on a single HCA frame and generate a PIL image object in RGBA
    color format, and a transparency property overlay image if applicable.

    This does full palette lookup and correctly handles dual color instead of
    making approximations using only half of the palette.

    The transparecy property overlay colors the pixels that need to be deleted
    from the canvas as red (#ff00007f) and pixels that need to be carried over
    from the canvas as green (#00ff007f).
    '''
    if frame is None and frame_index >= hca.nframes:
        raise ValueError(f'Frame {frame_index} does not exist.')

    byte_it: Iterator[int]
    if frame is None:
        frame = hca.frames[frame_index]

    if len(frame.data) == 0:
        return None, None

    if frame.header.frame_type == FrameType.COMPRESSED:
        byte_it = chain.from_iterable(BitstreamReader(BytesIO(frame.data)).decode())
    else:
        byte_it = iter(frame.data)

    # lpadding is in amount of input data bytes.
    if frame.header.lpadding != 0:
        byte_it = chain(repeat(0xff, frame.header.lpadding), byte_it)

    outbuf = BytesIO()
    erasebuf = BytesIO()

    def _write_outbuf(rgb12: int, t: bool):
        r = rgb12 & 0xf
        g = (rgb12 >> 4) & 0xf
        b = (rgb12 >> 8) & 0xf
        pixel = bytes((
            (r << 4) | r,
            (g << 4) | g,
            (b << 4) | b,
            0 if t else 255,
        ))
        outbuf.write(pixel)

    def _write_erasebuf(tc: bool, skip: bool):
        if skip:
            pixel = bytes((0, 255, 0, 127))
        else:
            if tc:
                pixel = bytes((255, 0, 0, 127))
            else:
                pixel = bytes((0, 0, 0, 127))

        erasebuf.write(pixel)

    if hca.pixel_format == PixelFormat.P8:
        pal = hca.palette
        assert isinstance(pal, HcaPalette8Bpp)
        colors = (pal.color_even, list((c >> 4 | c << 12) for c in pal.color_odd))
        ncolors = pal.size
        tc = hca.transparent_color_index
        tc_available = tc != 0xff
        for offset, index in enumerate(byte_it):
            # Make skip mark (0xff) implicitly transparent
            is_tc = tc_available and index == tc
            is_skip = tc_available and index == 0xff
            _write_outbuf(colors[offset % 2][index] if index < ncolors else 0, is_tc or is_skip)
            _write_erasebuf(is_tc, is_skip)

    elif hca.pixel_format == PixelFormat.P4:
        pal = hca.palette
        assert isinstance(pal, HcaPalette4Bpp)
        color = pal.color
        tc = hca.transparent_color_index
        tc_available = 0 <= tc < 16
        tc_has_skip = tc <= 15
        tctc = ((tc << 4) | tc) & 0xff
        for byte in byte_it:
            # The actual bitstream uses 4 UPPER bits to store the even pixel.
            cv = color[byte]
            if tc_available:
                is_tctc = tctc ^ byte
                is_tc0 = is_tctc & 0xf0 == 0
                is_tc1 = is_tctc & 0x0f == 0
            else:
                is_tc0 = False
                is_tc1 = False
            if tc_has_skip:
                is_skip0 = byte & 0xf0 == 0xf0
                is_skip1 = byte & 0x0f == 0x0f
            else:
                is_skip0 = False
                is_skip1 = False

            # Palette uses 12 LOWER bits to store the even pixel.
            rgb12_0 = cv & 0xfff
            rgb12_1 = (cv >> 12) & 0xfff

            _write_outbuf(rgb12_0, is_tc0 or is_skip0)
            _write_outbuf(rgb12_1, is_tc1 or is_skip1)
            _write_erasebuf(is_tc0, is_skip0)
            _write_erasebuf(is_tc1, is_skip1)

    elif hca.pixel_format == PixelFormat.RGB12:
        for twopixel in batched(byte_it, 3):
            pixels = int.from_bytes(bytes(twopixel), 'little')
            _write_outbuf(pixels & 0xfff, False)
            if len(twopixel) == 3:
                _write_outbuf((pixels >> 12) & 0xfff, False)

    else:
        raise NotImplementedError()

    # rpadding is implicit, so just fill the rest of the pixels with #00000000.
    # For the erase bitmap, fill with skip color (translucent green #00ff007f).
    padding = hca.padded_width * hca.height * 4 - len(outbuf.getvalue())
    if padding > 0:
        outbuf.write(b'\x00' * padding)
        erasebuf.write(bytes((0, 255, 0, 127)) * (padding // 4))

    out = Image.frombuffer(
        'RGBA', (hca.padded_width, hca.height), outbuf.getvalue(),
        'raw', 'RGBA', 0, 1
    )
    if hca.pixel_format != PixelFormat.RGB12:
        erase = Image.frombuffer(
            'RGBA', (hca.padded_width, hca.height), erasebuf.getvalue(),
            'raw', 'RGBA', 0, 1
        )
        return out, erase
    return out, None


def dump_all_hca_frames(hca: Hca, prefix: Path) -> None:
    for i, frame in enumerate(hca.frames):
        img, erase = dump_hca_frame(hca, frame=frame)
        if img is not None:
            with (prefix.parent / f'{prefix.name}_idx{i:03d}_seq{frame.header.seq:03d}.png').open('wb') as f:
                img.save(f)
        if erase is not None:
            with (prefix.parent / f'{prefix.stem}_idx{i:03d}_seq{frame.header.seq:03d}_e.png').open('wb') as f:
                erase.save(f)
