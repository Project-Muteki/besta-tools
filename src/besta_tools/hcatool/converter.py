from typing import Final


from collections.abc import Iterator, Sequence
from io import BytesIO
from itertools import batched, chain
from logging import getLogger
from pathlib import Path

from numpy import asarray, c_, dtype, ndarray, reshape, uint8, zeros
from numpy import empty as np_empty

from PIL import Image
from PIL.Image import Image as ImageType

from besta_tools.common.utils import align

from .formats import FrameType, Hca, HcaFrameContainer, HcaFrameHeader, HcaPalette4Bpp, HcaPalette8Bpp, HcaPaletteBase, PixelFormat
from .lzw import BitstreamReader, BitstreamWriter


logger = getLogger('besta_tools.hcatool.converter')


def pack_4b(inp: ndarray[tuple[int], dtype[uint8]]) -> ndarray[tuple[int], dtype[uint8]]:
    if inp.size % 2 != 0:
        raise ValueError('4b array input is not padded.')
    outp = np_empty(shape=inp.size // 2, dtype=uint8)
    outp[::] = (inp[0::2] << 4) | (inp[1::2] & 0xf)
    return outp


def unpack_4b(inp: ndarray[tuple[int], dtype[uint8]]) -> ndarray[tuple[int], dtype[uint8]]:
    outp = np_empty(shape=inp.size * 2, dtype=uint8)
    outp[0::2] = inp >> 4
    outp[1::2] = inp & 0xf
    return outp


PALETTE_SIZE_CAP: Final[dict[tuple[PixelFormat, bool], int]] = {
    (PixelFormat.P4, True): 16,
    (PixelFormat.P4, False): 15,
    (PixelFormat.P8, True): 256,
    (PixelFormat.P8, False): 255,
}


def try_compress(input_bytes: bytes) -> tuple[bool, bytes]:
    compress_writer = BytesIO()
    _ = BitstreamWriter(compress_writer).encode((input_bytes, ))
    compressed = compress_writer.getvalue()
    logger.debug('Compressed size %d, uncompressed size %d', len(compressed), len(input_bytes))
    if len(input_bytes) < len(compressed):
        return False, input_bytes
    else:
        return True, compressed


def frames_to_hca(input_frames: Sequence[ImageType], color_mode: PixelFormat, coalesce: bool = True) -> Hca:
    '''
    Convert `input_frames` into a single animated HCA object with the desired
    `color_mode`.

    Each image in `input_frames` must be in indexed mode, has the exact same
    dimension and uses the exact same palette. The palette can be in 8-bit RGB
    or RGBA format, but note that the RGBA palette must contain exactly zero or
    one color with the alpha value set to 0, and all the rest of the colors
    must have alpha value of 255.

    If the `coalesce` flag is set to `True`, the encoder will incorporate the
    frame images as-is into each HCA frame. Otherwise each frame image will be
    compared against its previous image to generate overlay frames.
    '''

    def _rgb12_safe(v: int) -> bool:
        return v & 0xf == v >> 4 or v & 0xf == 0

    if len(input_frames) == 0:
        raise ValueError('Must have at least one images.')
    elif len(input_frames) == 1:
        raise NotImplementedError()

    background = input_frames[0]
    if background.mode != 'P':
        raise ValueError(f'Input frame 0 is not in mode P.')
    assert background.palette is not None
    if background.palette.mode not in {'RGB', 'RGBA'}:
        raise ValueError(f'Unsupported mode {background.palette.mode} in frame 0.')

    width, height = background.size
    palette = background.palette
    palette_data = palette.getdata()

    tci = 0xff
    rgb12_unsafe = False

    # RGBA palette is poorly supported by major image editors but is possible.
    # We support a reduced subset of it.
    if palette.mode == 'RGBA':
        for c, i in palette.colors.items():
            assert len(c) == 4

            if c[3] == 0:
                if tci == 0xff:
                    tci = i
                else:
                    raise ValueError('More than one transparent color detected.')
            elif c[3] != 255:
                raise ValueError('Alpha value other than 0 and 255 is not allowed.')
    else:
        # Use the TCI exported in the info dictionary if present
        tcii = background.info.get('transparency', 0xff)
        assert isinstance(tcii, int)
        tci = tcii

    for c, i in palette.colors.items():
        if not _rgb12_safe(c[0]) or not _rgb12_safe(c[1]) or not _rgb12_safe(c[2]) and not rgb12_unsafe:
            rgb12_unsafe = True
            logger.warning(
                'Palette is not RGB12-safe. Colors will be clipped to ' +
                'the nearest RGB12 point. Consider quantizing the image to ' +
                'RGB12 to reduce color quality loss.'
            )

    palette_size = max(palette.colors.values()) + 1
    if palette_size > PALETTE_SIZE_CAP[color_mode, coalesce]:
        raise ValueError(f'Input palette is too large for palette format {color_mode.name}.')

    for index, frame in enumerate(input_frames[1:]):
        if frame.mode != 'P':
            raise ValueError(f'Input frame {index+1} is not in mode P.')
        assert frame.palette is not None
        if frame.palette.mode not in {'RGB', 'RGBA'}:
            raise ValueError(f'Unsupported mode {frame.palette.mode} in frame {index+1}.')
        if frame.palette.getdata() != palette_data:
            raise ValueError(f'Palette in frame {index+1} is not the same as frame 0.')
        if frame.width != width or frame.height != height:
            raise ValueError(f'Dimension of frame {index+1} is not the same as frame 0.')
        if frame.palette.mode == 'RGB' and frame.info.get('transparency', 0xff) != tci:
            raise ValueError(f'Transparent color of frame {index+1} is not the same as frame 0.')

    prev_remapped_2d: ndarray[tuple[int, int], dtype[uint8]] | None = None
    hca_frames: list[HcaFrameContainer] = []
    hca_palette: HcaPaletteBase
    if color_mode == PixelFormat.P4:
        hca_palette = HcaPalette4Bpp.from_rgb24(list((c[0], c[1], c[2]) for c in palette.colors.keys()))
    elif color_mode == PixelFormat.P8:
        hca_palette = HcaPalette8Bpp.from_rgb24(list((c[0], c[1], c[2]) for c in palette.colors.keys()))
    else:
        assert False
    hca = Hca(
        pixel_format=color_mode,
        height=height,
        width=width,
        transparent_color_index=tci,
        palette=hca_palette,
        frames=hca_frames,
    )
    for frame_index, frame in enumerate(input_frames):
        remapped_2d: ndarray[tuple[int, int], dtype[uint8]] = asarray(frame)

        # Pad the width to multiple of 4 and reshape to 1D
        padded_width = align(width, 4)
        remapped: ndarray[tuple[int], dtype[uint8]]
        if padded_width != width:
            logger.debug('Width unaligned, pad to %d', padded_width)
            # numpy did not type the index tricks yet
            remapped_2d = c_[  # pyright: ignore[reportAny]
                remapped_2d,
                zeros((padded_width - width, height), uint8)
            ]

        # Map same pixel between 2 frames to Skip Color, and remove leading and
        # trailing Skip color lines.
        lpadding_px = 0
        rpadding_px = padded_width * height
        is_empty = False
        if not coalesce:
            # Make a copy because we need to modify the buffer
            remapped_2d_orig = remapped_2d
            remapped_2d = remapped_2d.copy()
            if prev_remapped_2d is not None:
                diffmap: ndarray[tuple[int, int], dtype[uint8]] = remapped_2d ^ prev_remapped_2d
                remapped_2d[diffmap == 0] = (0xf if color_mode == PixelFormat.P4 else 0xff)
                # Non-zero values will be from the different pixels.
                nz = diffmap.nonzero()
                if len(nz[0]) == 0:
                    is_empty = True
                else:
                    # Intentionally align to the start of pixel line to stay
                    # consistent with Besta's HCATOOL, although even without
                    # the alignment, the decoder of both HCATOOL and HCAView
                    # do seem to work correctly as well.
                    lpadding_px = int(nz[0][0]) * padded_width
                if len(nz[1]) > 1:
                    rpadding_px = min(int(nz[0][-1]) * padded_width + int(nz[1][-1]) + 1, rpadding_px)
            prev_remapped_2d = remapped_2d_orig

        logger.debug(
            'Left pad offset %d, right pad offset %d',
            lpadding_px,
            rpadding_px
        )

        remapped = reshape(remapped_2d, shape=padded_width * height)

        lpadding = lpadding_px
        rpadding = rpadding_px
        if color_mode == PixelFormat.P4:
            logger.debug('Pack the frame into 4-bit buffer')
            remapped = pack_4b(remapped)
            lpadding //= 2
            rpadding //= 2
        remapped_bytes = remapped.tobytes()

        if not coalesce:
            if lpadding != 0 or rpadding != len(remapped_bytes):
                # TODO: can we pass memoryview to the LZW encoder?
                remapped_bytes = remapped_bytes[lpadding:rpadding]

        if is_empty:
            hca_frame = HcaFrameContainer(
                header=HcaFrameHeader(
                    frame_type=FrameType.UNCOMPRESSED,
                    seq=max(frame_index - 1, 0),
                    lpadding=0xffffffff,
                ),
                data=b'',
            )
        else:
            is_compressed, frame_data = try_compress(remapped_bytes)
            hca_frame = HcaFrameContainer(
                header=HcaFrameHeader(
                    frame_type=FrameType.COMPRESSED if is_compressed else FrameType.UNCOMPRESSED,
                    seq=max(frame_index - 1, 0),
                    lpadding=lpadding,
                ),
                data=frame_data,
            )
        hca_frames.append(hca_frame)

    return hca


def dump_hca_frame(hca: Hca, frame_index: int = 0, frame: HcaFrameContainer | None = None) -> tuple[ImageType | None, ImageType | None, int]:
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
        return None, None, 0

    if frame.header.frame_type == FrameType.COMPRESSED:
        decoder = BitstreamReader(BytesIO(frame.data)).decode()
        byte_it = chain.from_iterable(decoder)
    else:
        decoder = None
        byte_it = iter(frame.data)

    if frame.header.lpadding % hca.pitch != 0:
        logger.warning(f'lpadding {frame.header.lpadding} does not align with pitch {hca.pitch}.')

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

    if frame.header.frame_type == FrameType.COMPRESSED:
        assert decoder is not None
        input_count = decoder.num_bytes_written
    else:
        input_count = len(frame.data)

    if input_count % hca.pitch != 0:
        logger.warning(f'rpadding {input_count} does not align with pitch {hca.pitch}.')

    out_height = int(input_count // hca.pitch)

    out = Image.frombuffer(
        'RGBA', (hca.padded_width, out_height), outbuf.getvalue(),
        'raw', 'RGBA', 0, 1
    )
    if hca.pixel_format != PixelFormat.RGB12:
        erase = Image.frombuffer(
            'RGBA', (hca.padded_width, out_height), erasebuf.getvalue(),
            'raw', 'RGBA', 0, 1
        )
        return out, erase, int(frame.header.lpadding // hca.pitch)
    return out, None, int(frame.header.lpadding // hca.pitch)


def dump_all_hca_frames(hca: Hca, prefix: Path) -> None:
    for i, frame in enumerate(hca.frames):
        img, erase, height = dump_hca_frame(hca, frame=frame)
        if img is not None:
            with (prefix.parent / f'{prefix.name}_idx{i:03d}_seq{frame.header.seq:03d}_+{height}.png').open('wb') as f:
                img.save(f)
        if erase is not None:
            with (prefix.parent / f'{prefix.stem}_idx{i:03d}_seq{frame.header.seq:03d}_+{height}_e.png').open('wb') as f:
                erase.save(f)
