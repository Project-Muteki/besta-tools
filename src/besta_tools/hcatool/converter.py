from typing import Final

from collections.abc import Sequence
from io import BytesIO
from itertools import chain, product
from logging import getLogger
from pathlib import Path

from numpy import array, asarray, bool_, c_, dtype, empty, frombuffer, fromiter, full, ndarray, uint8, zeros
from numpy.typing import NDArray

from PIL.Image import Image, fromarray as npa2image

from besta_tools.common.utils import align

from .formats import FrameType, Hca, HcaFrameContainer, HcaFrameHeader, HcaPalette4Bpp, HcaPalette8Bpp, HcaPaletteBase, HcaPaletteDummy, PixelFormat
from .lzw import BitstreamReader, BitstreamWriter


logger = getLogger('besta_tools.hcatool.converter')


type PaletteDump = tuple[str, Sequence[int] | bytes | bytearray]


def pack_4b(inp: NDArray[uint8]) -> NDArray[uint8]:
    if inp.dtype != uint8:
        raise TypeError('Input must be an uint8 array.')
    if inp.ndim == 0:
        raise ValueError('Packing 0 dimension array does not make sense.')
    if inp.shape[-1] % 2 != 0:
        raise ValueError('Last axis length must be a multiple of 2.')
    assert inp.size % 2 == 0

    flattened = inp.reshape(inp.size)
    outp = empty(shape=inp.size // 2, dtype=uint8)
    outp[::] = (flattened[0::2] << 4) | (flattened[1::2] & 0xf)

    return outp.reshape((*inp.shape[:-1], inp.shape[-1] // 2))


def unpack_4b(inp: NDArray[uint8]) -> NDArray[uint8]:
    if inp.ndim == 0:
        raise ValueError('Packing 0 dimension array does not make sense.')

    flattened = inp.reshape(inp.size)
    outp = empty(shape=inp.size * 2, dtype=uint8)
    outp[0::2] = flattened >> 4
    outp[1::2] = flattened & 0xf
    return outp.reshape((*inp.shape[:-1], inp.shape[-1] * 2))


PALETTE_SIZE_CAP: Final[dict[tuple[PixelFormat, bool], int]] = {
    (PixelFormat.P4, True): 16,
    (PixelFormat.P4, False): 15,
    (PixelFormat.P8, True): 256,
    (PixelFormat.P8, False): 255,
}


def _compress(input_bytes: bytes) -> bytes:
    compress_writer = BytesIO()
    _ = BitstreamWriter(compress_writer).encode((input_bytes, ))
    compressed = compress_writer.getvalue()
    logger.debug('Compressed size %d, uncompressed size %d', len(compressed), len(input_bytes))
    return compressed


def try_compress(input_bytes: bytes, compress: bool | None = None) -> tuple[bool, bytes]:
    if compress is None:
        compressed = _compress(input_bytes)
        if len(input_bytes) < len(compressed):
            return False, input_bytes
        else:
            return True, compressed
    elif compress:
        return True, _compress(input_bytes)
    else:
        return False, input_bytes


def _convert_palette(template: Image, color_mode: PixelFormat, coalesce: bool) -> tuple[int, PaletteDump, HcaPaletteBase]:
    def _rgb12_safe(v: int) -> bool:
        return v & 0xf == v >> 4 or v & 0xf == 0

    if color_mode == PixelFormat.RGB12:
        raise TypeError('RGB12 color mode does not need a palette.')
    if template.mode != 'P':
        raise TypeError(f'Palette template image is not in mode P.')
    assert template.palette is not None
    logger.debug('Image uses %s palette format (rawmode is %s)', template.palette.mode, template.palette.rawmode)
    if template.palette.mode not in {'RGB', 'RGBA'}:
        raise TypeError(f'Unsupported mode {template.palette.mode} in palette template.')

    palette = template.palette
    palette_data: PaletteDump = palette.getdata()

    logger.debug('Parsed palette: %s', palette.colors)
    logger.debug('Raw palette: %s', palette_data)

    # HACK: This is required to convert certain non-native palette format into
    # a native one, or Pillow will interpret them wrong and cause palette.color
    # to contain garbage.
    _ = template.getpalette(palette.mode)

    tci = 0xff
    rgb12_unsafe = False

    # RGBA palette is poorly supported by major image editors but having them
    # is still possible. We try to support a reduced subset of it.
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
        logger.debug('TCI determined by RGBA palette to be 0x%x', tci)
    else:
        # Use the TCI exported in the info dictionary if present
        tcii = template.info.get('transparency', 0xff)  # pyright: ignore[reportAny], we'll check later
        assert isinstance(tcii, int)
        tci = tcii
        logger.debug('TCI determined by image metadata to be 0x%x', tci)

    for c, i in palette.colors.items():
        if not _rgb12_safe(c[0]) or not _rgb12_safe(c[1]) or not _rgb12_safe(c[2]) and not rgb12_unsafe:
            rgb12_unsafe = True
            logger.warning(
                'Palette is not RGB12-safe. Colors will be clipped to ' +
                'the nearest RGB12 point. Consider quantizing the image to ' +
                'RGB12 to reduce color quality loss.'
            )
            break

    palette_size = max(palette.colors.values()) + 1
    if palette_size > PALETTE_SIZE_CAP[color_mode, coalesce]:
        raise ValueError(f'Input palette is too large for palette format {color_mode.name}.')

    # Rebuild the palette as a sorted array as the iterator may not return them
    # in index order
    for_hcapalette: list[tuple[int, int, int]] = list(
        (0, 0, 0) for _ in range(palette_size)
    )
    for c, i in palette.colors.items():
        for_hcapalette[i] = (c[0], c[1], c[2])

    if color_mode == PixelFormat.P4:
        return tci, palette_data, HcaPalette4Bpp.from_rgb24(for_hcapalette)
    elif color_mode == PixelFormat.P8:
        return tci, palette_data, HcaPalette8Bpp.from_rgb24(for_hcapalette)


def frames_to_hca(
    input_frames: Sequence[Image],
    color_mode: PixelFormat,
    coalesce: bool = True,
    compress: bool | None = None
) -> Hca:
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

    if len(input_frames) == 0:
        raise ValueError('Must have at least one images.')
    elif len(input_frames) == 1:
        return image_to_hca(input_frames[0], color_mode, compress)

    background = input_frames[0]
    width, height = background.size

    tci, palette_data, hca_palette = _convert_palette(background, color_mode, coalesce)

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

    prev_data_2d: ndarray[tuple[int, int], dtype[uint8]] | None = None
    hca_frames: list[HcaFrameContainer] = []

    hca = Hca(
        pixel_format=color_mode,
        height=height,
        width=width,
        transparent_color_index=tci,
        palette=hca_palette,
        frames=hca_frames,
    )
    for frame_index, frame in enumerate(input_frames):
        data_2d: ndarray[tuple[int, int], dtype[uint8]] = asarray(frame)

        # Pad the width to multiple of 4
        padded_width = align(width, 4)
        data_1d: ndarray[tuple[int], dtype[uint8]]
        if padded_width != width:
            logger.debug('Width unaligned, pad to %d', padded_width)
            # numpy did not type the index tricks yet
            data_2d = c_[  # pyright: ignore[reportAny]
                data_2d,
                zeros((padded_width - width, height), uint8)
            ]

        if color_mode == PixelFormat.P4:
            logger.debug('Pack the frame into 4-bit buffer')
            data_2d = pack_4b(data_2d)

        # Map same byte between 2 frames to Skip Mark, and remove leading and
        # trailing Skip Mark lines.
        lslice = 0
        rslice = data_2d.size
        is_empty = False
        if not coalesce:
            # Make a copy because we need to modify the buffer
            data_2d_orig = data_2d
            data_2d = data_2d.copy()
            if prev_data_2d is not None:
                diffmap: ndarray[tuple[int, int], dtype[uint8]] = data_2d ^ prev_data_2d
                data_2d[diffmap == 0] = 0xff
                # Non-zero values will be from the changing pixels.
                nz = diffmap.nonzero()
                if len(nz[0]) == 0:
                    is_empty = True
                else:
                    # Intentionally align to the start of pixel lines to stay
                    # consistent with Besta's HCATOOL, although even without
                    # the alignment, the decoder of both HCATOOL and HCAView
                    # do seem to work correctly as well.
                    lslice = int(nz[0][0]) * data_2d.shape[1]
                    if len(nz[1]) > 1:
                        rslice = min((int(nz[0][-1]) + 1) * data_2d.shape[1], rslice)
            prev_data_2d = data_2d_orig

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
            data_1d = data_2d.reshape(data_2d.size)
            if not coalesce and (lslice != 0 or rslice != data_1d.size):
                data_1d = data_1d[lslice:rslice]
            data_bytes = data_1d.tobytes()

            is_compressed, frame_data = try_compress(data_bytes, compress)
            hca_frame = HcaFrameContainer(
                header=HcaFrameHeader(
                    frame_type=FrameType.COMPRESSED if is_compressed else FrameType.UNCOMPRESSED,
                    seq=max(frame_index - 1, 0),
                    lpadding=lslice,
                ),
                data=frame_data,
            )
        hca_frames.append(hca_frame)

    return hca


def _clip_rgb24_to_rgb12(rgb24: ndarray[tuple[int, int, int], dtype[uint8]]) -> ndarray[tuple[int, int, int], dtype[uint8]]:
    '''
    Vectorized routine that converts a RGB24 raw image into Besta RGB12.
    '''
    assert rgb24.size % 6 == 0

    clipped = rgb24 // 16
    outp = empty((rgb24.shape[0], rgb24.shape[1] // 2, rgb24.shape[2]), uint8)
    outp[..., 0] = clipped[:, 0::2, 0] | (clipped[:, 0::2, 1] << 4)
    outp[..., 1] = clipped[:, 0::2, 2] | (clipped[:, 1::2, 0] << 4)
    outp[..., 2] = clipped[:, 1::2, 1] | (clipped[:, 1::2, 2] << 4)
    return outp


def image_to_hca(
    input_image: Image,
    color_mode: PixelFormat,
    compress: bool | None = None,
) -> Hca:
    data_bytes: bytes
    hca_palette: HcaPaletteBase
    tci: int

    if color_mode == PixelFormat.RGB12:
        if input_image.width % 4 != 0:
            raise ValueError('Image width must be a multiple of 4 in RGB12 mode.')
        image_rgb = input_image.convert('RGB')
        data_2d: ndarray[tuple[int, int, int], dtype[uint8]] = asarray(image_rgb)
        assert data_2d.ndim == 3 and data_2d.dtype == uint8
        data_clipped = _clip_rgb24_to_rgb12(data_2d)
        hca_palette = HcaPaletteDummy()
        data_bytes = data_clipped.tobytes()
        tci = 0xff
    else:
        tci, _, hca_palette = _convert_palette(input_image, color_mode, True)
        data_2d = asarray(input_image)
        # Pad the width to multiple of 4
        padded_width = align(input_image.width, 4)
        if padded_width != input_image.width:
            logger.debug('Width unaligned, pad to %d', padded_width)
            # numpy did not type the index tricks yet
            data_2d = c_[  # pyright: ignore[reportAny]
                data_2d,
                zeros((padded_width - input_image.width, input_image.height), uint8)
            ]
        if color_mode == PixelFormat.P4:
            data_2d = pack_4b(data_2d)
        data_bytes = data_2d.tobytes()

    is_compressed, frame_data = try_compress(data_bytes, compress)
    hca_frame = HcaFrameContainer(
        header=HcaFrameHeader(
            frame_type=FrameType.COMPRESSED if is_compressed else FrameType.UNCOMPRESSED,
            seq=0,
            lpadding=0,
        ),
        data=frame_data,
    )

    return Hca(
        pixel_format=color_mode,
        height=input_image.height,
        width=input_image.width,
        transparent_color_index=tci,
        palette=hca_palette,
        frames=[hca_frame],
    )


def dump_hca_frame(hca: Hca, frame_index: int = 0, frame: HcaFrameContainer | None = None) -> tuple[Image | None, Image | None]:
    '''
    Apply palette on a single HCA frame and generate a PIL image object in RGBA
    color format, and a transparency property overlay image if applicable.

    This does full palette lookup and correctly handles dual color instead of
    making approximations using only half of the palette.

    The transparecy property overlay colors the pixels that need to be deleted
    from the canvas as red (#ff00007f) and pixels that need to be carried over
    from the canvas as green (#00ff007f).
    '''
    TPO_SKIP: Final = (0, 255, 0, 127)
    TPO_TC: Final = (255, 0, 0, 127)
    TPO_NOP: Final = (255, 255, 255, 127)

    if frame is None and frame_index >= hca.nframes:
        raise ValueError(f'Frame {frame_index} does not exist.')

    if frame is None:
        frame = hca.frames[frame_index]

    if len(frame.data) == 0:
        return None, None

    data_1d: ndarray[tuple[int], dtype[uint8]]
    if frame.header.frame_type == FrameType.COMPRESSED:
        decoder = BitstreamReader(BytesIO(frame.data)).decode()
        data_1d = fromiter(chain.from_iterable(decoder), dtype=uint8)
    else:
        data_1d = frombuffer(frame.data, dtype=uint8)

    padded_size = hca.pitch * hca.height
    if data_1d.size < padded_size:
        data_1d_padded = full(padded_size, fill_value=0xff, dtype=uint8)
        data_1d_padded[frame.header.lpadding:frame.header.lpadding+data_1d.size] = data_1d
        data_1d = data_1d_padded

    padded_width = align(hca.width, 4)
    shape_1d = (padded_width * hca.height, 4)
    rgba_1d = zeros(shape_1d, uint8)
    tpo_1d = full(shape_1d, fill_value=TPO_NOP, dtype=uint8)

    if hca.pixel_format == PixelFormat.RGB12:
        for ppos, cpos in product(range(2), range(3)):
            nibble = ppos * 3 + cpos
            byte = nibble // 2
            if nibble % 2 == 0:
                color = data_1d[byte::3] & 0xf
            else:
                color = (data_1d[byte::3] >> 4) & 0xf
            rgba_1d[ppos::2, cpos] = (color << 4) | color
        rgba_1d[:, 3] = 255

    elif hca.pixel_format == PixelFormat.P8:
        # Provide an odd-even view of the data for convenience
        data_1d_vec = data_1d.reshape((data_1d.shape[0] // 2, 2))

        # Change the shape to align with input data.
        shape_1d_vec = (shape_1d[0] // 2, 2, shape_1d[1])
        rgba_1d_vec = rgba_1d.reshape(shape_1d_vec)

        # Generate transparent color and skip mark mapping
        if hca.palette.size < 256:
            skip_mark_indices = data_1d == 0xff
        else:
            logger.debug('Image disables skip mark. Use all zero skip mark map.')
            skip_mark_indices = zeros(data_1d.shape, bool_)
        
        if hca.transparent_color_index != 255:
            tc_indices = data_1d == hca.transparent_color_index
        else:
            logger.debug('Image disables transparent color. Use all zero transparent color map.')
            tc_indices = zeros(data_1d.shape, bool_)

        # Mark transparency on TPO
        tpo_1d[tc_indices, 0:4] = TPO_TC
        tpo_1d[skip_mark_indices, 0:4] = TPO_SKIP

        # Expand redundant palette
        assert isinstance(hca.palette, HcaPalette8Bpp)

        palette_even = array(hca.palette.color_even_as_rgb24(), uint8)
        palette_odd = array(hca.palette.color_odd_as_rgb24(), uint8)

        # Mask off skip marks to avoid out of bound access.
        not_skip_mark_indices_even = ~(skip_mark_indices[0::2])
        not_skip_mark_indices_odd = ~(skip_mark_indices[1::2])

        # Color lookup
        rgba_1d_vec[..., 3] = 255
        rgba_1d_vec[not_skip_mark_indices_even, 0, 0:3] = palette_even[data_1d_vec[not_skip_mark_indices_even, 0]]
        rgba_1d_vec[not_skip_mark_indices_odd, 1, 0:3] = palette_odd[data_1d_vec[not_skip_mark_indices_odd, 1]]
        rgba_1d[skip_mark_indices | tc_indices, 3] = 0

    elif hca.pixel_format == PixelFormat.P4:
        # Change the shape to align with input data.
        shape_1d_vec = (shape_1d[0] // 2, 2, shape_1d[1])
        rgba_1d_vec = rgba_1d.reshape(shape_1d_vec)
        tpo_1d_vec = tpo_1d.reshape(shape_1d_vec)

        # Generate transparent color and skip mark mapping
        if hca.palette.size < 16:
            skip_mark_indices = data_1d == 0xff
        else:
            logger.debug('Image disables skip mark. Use all zero skip mark map.')
            skip_mark_indices = zeros(data_1d.shape, bool_)

        if hca.transparent_color_index != 255:
            tc_indices_odd = (data_1d & 0xf) == hca.transparent_color_index
            tc_indices_even = (data_1d & 0xf0) == hca.transparent_color_index << 4
        else:
            logger.debug('Image disables transparent color. Use all zero transparent color map.')
            tc_indices_odd = tc_indices_even = zeros(data_1d.shape, bool_)

        # Mark transparency on TPO
        tpo_1d_vec[tc_indices_even, 0, 0:4] = TPO_TC
        tpo_1d_vec[tc_indices_odd, 1, 0:4] = TPO_TC
        tpo_1d_vec[skip_mark_indices, :, 0:4] = TPO_SKIP

        # Expand redundant palette
        assert isinstance(hca.palette, HcaPalette4Bpp)

        palette_vec = array(hca.palette.color_as_rgb24(), uint8)

        # Color lookup
        rgba_1d_vec[..., 3] = 255
        rgba_1d_vec[~skip_mark_indices, 0, 0:3] = palette_vec[data_1d[~skip_mark_indices], 0]
        rgba_1d_vec[~skip_mark_indices, 1, 0:3] = palette_vec[data_1d[~skip_mark_indices], 1]
        rgba_1d_vec[skip_mark_indices, :, 3] = 0
        rgba_1d_vec[tc_indices_even, 0, 3] = 0
        rgba_1d_vec[tc_indices_odd, 1, 3] = 0

    rgba_img = npa2image(rgba_1d.reshape((hca.height, padded_width, 4)), 'RGBA')
    tpo_img = npa2image(tpo_1d.reshape((hca.height, padded_width, 4)), 'RGBA')

    return rgba_img, tpo_img


def dump_all_hca_frames(hca: Hca, prefix: Path) -> None:
    for i, frame in enumerate(hca.frames):
        img, erase = dump_hca_frame(hca, frame=frame)
        if img is not None:
            with (prefix.parent / f'{prefix.name}_idx{i:03d}_seq{frame.header.seq:03d}.png').open('wb') as f:
                img.save(f)
        if erase is not None:
            with (prefix.parent / f'{prefix.stem}_idx{i:03d}_seq{frame.header.seq:03d}_e.png').open('wb') as f:
                erase.save(f)
