'''
HCA constructs and helper functions.

The construct part is more or less a straight port of the hca.hexpat pattern,
with many advanced features of construct being used to reduce post-parser code
complexity, while maintaining the flexibility of the resulting objects.
'''

from abc import ABC, abstractmethod
from collections.abc import Generator, Sequence
from dataclasses import dataclass, field
from itertools import islice
from typing import TYPE_CHECKING, Self, cast, override

from construct import Array, Bytes, Check, Computed, Const, If, IfThenElse, Int16ul, Int32ul, Int8ul, Pass, Rebuild, Switch, ValidationError, len_, this
from construct_typed import DataclassMixin, DataclassStruct, EnumBase, TEnum, csfield, csfield_const, csfield_default, csfield_noinit

from besta_tools.common.utils import align


if TYPE_CHECKING:
    from construct_typed import Context
    from _typeshed import MaybeNone


class PixelFormat(EnumBase):
    P4 = 0x0f
    P8 = 0xff
    RGB12 = 0xc0


CsPixelFormat = TEnum(Int8ul, PixelFormat)


class FrameType(EnumBase):
    COMPRESSED = ord('F') | (ord('C') << 8)
    UNCOMPRESSED = ord('F') | (ord('U') << 8)


CsFrameType = TEnum(Int16ul, FrameType)


class HcaPaletteBase(ABC):
    @staticmethod
    def _mag_to_4b(mag: float) -> int:
        return round(min(max(mag, 0.0), 1.0) * 0xf)

    @property
    @abstractmethod
    def size(self) -> int:
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def from_rgb12(cls, rgb12s: Sequence[int]) -> Self:
        raise NotImplementedError()

    @classmethod
    def from_rgb(cls, rgb: Sequence[tuple[float, float, float]]) -> Self:
        rgb12 = list(
            cls._mag_to_4b(r) |
                cls._mag_to_4b(g) << 4 |
                cls._mag_to_4b(b) << 8
            for r, g, b in rgb
        )
        return cls.from_rgb12(rgb12)

    @classmethod
    def from_rgb24(cls, rgb: Sequence[tuple[int, int, int]]) -> Self:
        rgb12 = list(
            ((r >> 4) & 0xf) |
                (((g >> 4) & 0xf) << 4) |
                (((b >> 4) & 0xf) << 8)
            for r, g, b in rgb
        )
        return cls.from_rgb12(rgb12)

    @abstractmethod
    def to_rgb12(self) -> list[int]:
        raise NotImplementedError()

    def to_rgb12_tuples(self) -> list[tuple[int, int, int]]:
        return list(
            (
                c & 0xf,
                (c >> 4) & 0xf,
                (c >> 8) & 0xf,
            ) for c in self.to_rgb12()
        )

    def to_rgb(self) -> list[tuple[float, float, float]]:
        return list(
            (
                (c & 0xf) / 0xf,
                ((c >> 4) & 0xf) / 0xf,
                ((c >> 8) & 0xf) / 0xf
            ) for c in self.to_rgb12()
        )

    def to_rgb24(self) -> list[tuple[int, int, int]]:
        def _iter():
            for c in self.to_rgb12():
                r = c & 0xf
                g = (c >> 4) & 0xf
                b = (c >> 8) & 0xf
                yield (r << 4) | r, (g << 4) | g, (b << 4) | b

        return list(_iter())


# We intentionally do not use construct to rebuild the palette so we can get
# maximum flexibility on its content (like exploring the possibility of more
# than 16/256 colors on indexed image by abusing its unique vectored palette
# format).
@dataclass
class HcaPalette8Bpp(DataclassMixin, HcaPaletteBase):
    _len: int | None = csfield_noinit(cast('Computed[int]', Computed(this._.palette_size)))
    color_even: list[int] = csfield(Array(this._len, Int16ul))
    color_odd: list[int] = csfield(Array(this._len, Int16ul))

    @property
    @override
    def size(self) -> int:
        return len(self.color_even)

    @classmethod
    @override
    def from_rgb12(cls, rgb12s: Sequence[int]) -> Self:
        return cls(color_even=list(rgb12s), color_odd=[(c << 4) | (c >> 12) for c in rgb12s])

    @override
    def to_rgb12(self) -> list[int]:
        return list(self.color_even)

    def _color_even_as_iter(self) -> Generator[tuple[int, int, int]]:
        return (
            (
                c & 0xf,
                (c >> 4) & 0xf,
                (c >> 8) & 0xf,
            ) for c in self.color_even
        )

    def _color_odd_as_iter(self) -> Generator[tuple[int, int, int]]:
        return (
            (
                (c >> 4) & 0xf,
                (c >> 8) & 0xf,
                (c >> 12) & 0xf,
            ) for c in self.color_odd
        )

    def color_even_as_rgb12(self) -> list[tuple[int, int, int]]:
        return list(self._color_even_as_iter())

    def color_even_as_rgb24(self) -> list[tuple[int, int, int]]:
        return list(
            (
                (c[0] << 4) | c[0],
                (c[1] << 4) | c[1],
                (c[2] << 4) | c[2],
            ) for c in self._color_even_as_iter()
        )

    def color_odd_as_rgb12(self) -> list[tuple[int, int, int]]:
        return list(self._color_odd_as_iter())

    def color_odd_as_rgb24(self) -> list[tuple[int, int, int]]:
        return list(
            (
                (c[0] << 4) | c[0],
                (c[1] << 4) | c[1],
                (c[2] << 4) | c[2],
            ) for c in self._color_odd_as_iter()
        )


CsHcaPalette8Bpp = DataclassStruct(HcaPalette8Bpp)


@dataclass
class HcaPalette4Bpp(DataclassMixin, HcaPaletteBase):
    _len: int | None = csfield_noinit(cast('Computed[int]', Computed(this._.palette_size)))
    color: list[int] = csfield(Array(16 * 16, Int32ul))
    # HACK: This is a pure Python field that is used to help reading palette
    # data. Manually specify the subcon to Pass here to let construct_typing
    # safely ignore this field.
    len_: int = field(default=0, metadata={'subcon': Pass})

    @property
    @override
    def size(self) -> int:
        if self._len is not None and self._len != self.len_:
            self.len_ = self._len
        return self.len_

    @classmethod
    @override
    def from_rgb12(cls, rgb12s: Sequence[int]) -> Self:
        if len(rgb12s) > 16:
            raise ValueError('Palette must have no more than 16 entries.')
        sparse = dict(enumerate(rgb12s))

        res = cls(color=[(sparse.get(x, 0) << 12) | sparse.get(y, 0) for y in range(16) for x in range(16)], len_=len(rgb12s))
        res._len = res.len_

        return res

    @override
    def to_rgb12(self) -> list[int]:
        return [(c >> 12) & 0xfff for c in islice(self.color, self.size)]

    def color_as_iter(self) -> Generator[tuple[tuple[int, int, int], tuple[int, int, int]]]:
        return (
            (
                (cc & 0xf, (cc >> 4) & 0xf, (cc >> 8) & 0xf),
                ((cc >> 12) & 0xf, (cc >> 16) & 0xf, (cc >> 20) & 0xf)
            ) for cc in self.color
        )

    def color_as_rgb12(self) -> list[tuple[tuple[int, int, int], tuple[int, int, int]]]:
        return list(self.color_as_iter())

    def color_as_rgb24(self) -> list[tuple[tuple[int, int, int], tuple[int, int, int]]]:
        return list(
            ((
                (c0[0] << 4) | c0[0],
                (c0[1] << 4) | c0[1],
                (c0[2] << 4) | c0[2],
            ),
            (
                (c1[0] << 4) | c1[0],
                (c1[1] << 4) | c1[1],
                (c1[2] << 4) | c1[2],
            )) for c0, c1 in self.color_as_iter()
        )


CsHcaPalette4Bpp = DataclassStruct(HcaPalette4Bpp)


@dataclass
class HcaPaletteDummy(DataclassMixin, HcaPaletteBase):
    '''
    Empty palette class so we can mount our stuff onto it.
    '''
    _color: None = csfield_noinit(Pass)

    @property
    @override
    def size(self) -> int:
        return 0

    @classmethod
    @override
    def from_rgb12(cls, rgb12s: Sequence[int]) -> Self:
        return cls()

    @override
    def to_rgb12(self) -> list[int]:
        return []


CsHcaPaletteDummy = DataclassStruct(HcaPaletteDummy)


@dataclass
class HcaFrameHeader(DataclassMixin):
    frame_type: FrameType = csfield(CsFrameType)
    seq: int = csfield( Int16ul)
    lpadding: int = csfield(Int32ul)
    _sbz_0x8: int | None = csfield_const(Int8ul, 0)
    _padding: bytes | None = csfield_default(Bytes(3), default=b'\x00\x00\x00')


CsHcaFrameHeader = DataclassStruct(HcaFrameHeader)


@dataclass
class HcaFrameContainer(DataclassMixin):
    _len: int | None = csfield_noinit(IfThenElse(
        this._index == this._._nframes - 1,
        cast(
            'Computed[int]',
            Computed(
                lambda ctx: (
                    ctx._._data_size -
                    ctx._._frame_offsets[ctx._index] -
                    CsHcaFrameHeader.sizeof()
                )
            )
        ),
        cast(
            'Computed[int]',
            Computed(
                lambda ctx: (
                    ctx._._frame_offsets[ctx._index + 1] -
                    ctx._._frame_offsets[ctx._index] -
                    CsHcaFrameHeader.sizeof()
                )
            )
        ),
    ))
    header: HcaFrameHeader = csfield(CsHcaFrameHeader)
    data: bytes = csfield(Bytes(this._len))


CsHcaFrameContainer = DataclassStruct(HcaFrameContainer)


def rebuild_hca_data_size(ctx: 'Context') -> int:
    return sum(len(frame.data) + CsHcaFrameHeader.sizeof() for frame in ctx.frames)


def rebuild_hca_frame_offsets(ctx: 'Context') -> list[int]:
    result: list[int] = []
    acc = 0
    for frame in ctx.frames:
        result.append(acc)
        acc += len(frame.data) + CsHcaFrameHeader.sizeof()
    return result


def rebuild_8bpp_palette_length(ctx: 'Context') -> int:
    len_ = len(ctx.palette.color_even)
    if len_ > 256:
        raise ValidationError('8Bpp palette size cannot exceed 256 entries.')
    if len_ == 256:
        return 0
    else:
        return len_


@dataclass
class Hca(DataclassMixin):
    magic: bytes = csfield_const(Bytes(3), b'HCA')
    pixel_format: PixelFormat = csfield(CsPixelFormat)
    height: int = csfield(Int16ul)
    width: int = csfield(Int16ul)
    _width_check: None = csfield_noinit(
        If(this.pixel_format == PixelFormat.RGB12, Check(this.width % 4 == 0))
    )
    _nframes: 'int | MaybeNone' = csfield_noinit(Rebuild(Int8ul, len_(this.frames)))
    # Intentionally don't cast the Switch so it can stay as a "can build from
    # None" type.
    raw_palette_size: 'int | MaybeNone' = csfield_noinit(
        Switch(this.pixel_format, {
            PixelFormat.P4: Rebuild(Int8ul, this.palette.size),
            PixelFormat.P8: Rebuild(
                Int8ul,
                rebuild_8bpp_palette_length,
            ),
            PixelFormat.RGB12: Const(0, Int8ul),
        })
    )
    palette_size: 'int | MaybeNone' = csfield_noinit(cast(
        'Computed[int]',
        Computed(lambda ctx: (
            256
            if ctx.pixel_format == PixelFormat.P8 and ctx.raw_palette_size == 0
            else ctx.raw_palette_size
        )),
    ))
    _nframes2: int | None = csfield_noinit(Rebuild(Int8ul, len_(this.frames)))
    _check_nframes_match: None = csfield_noinit(Check(this._nframes == this._nframes2))
    transparent_color_index: int = csfield(Int8ul)
    palette: HcaPaletteBase = csfield(subcon=cast(
        'Switch[HcaPaletteBase, HcaPaletteBase]',
        Switch(this.pixel_format, {
            PixelFormat.P4: CsHcaPalette4Bpp,
            PixelFormat.P8: CsHcaPalette8Bpp,
            PixelFormat.RGB12: CsHcaPaletteDummy,
        })
    ))
    _data_size: int | None = csfield_noinit(Rebuild(Int32ul, rebuild_hca_data_size))
    _frame_offsets: list[int] | None = csfield_noinit(Rebuild(Array(this._nframes, Int32ul), rebuild_hca_frame_offsets))
    frames: list[HcaFrameContainer] = csfield(Array(this._nframes, CsHcaFrameContainer))

    @property
    def pitch(self) -> int:
        '''
        Convenience method to estimate the pitch of the frame data (# of bytes
        per line).
        '''
        if self.pixel_format == PixelFormat.P8:
            return align(self.width, 4)
        elif self.pixel_format == PixelFormat.P4:
            return align(self.width, 4) // 2
        elif self.pixel_format == PixelFormat.RGB12:
            return self.width * 12 // 8
        else:
            raise ValueError(f'Unknown pixel format {repr(self.pixel_format)}')

    @property
    def padded_width(self) -> int:
        '''
        Convenience method to estimate the padded width of the frames in
        pixels.
        '''
        if self.pixel_format == PixelFormat.P8 or self.pixel_format == PixelFormat.P4:
            return align(self.width, 4)
        else:
            # I wasn't able to get Besta HCATool to output any RGB12 image
            # that has a width that is not 4-bytes aligned.
            return self.width

    @property
    def allow_transparency(self) -> bool:
        '''
        Convenience method to check whether transparency processing should be
        enabled.
        '''
        return (
            self.pixel_format != PixelFormat.RGB12 and
            self.transparent_color_index != 0xff
        )

    @property
    def allow_skip(self) -> bool:
        '''
        Convenience method to check whether skip mark processing should be
        enabled.
        '''
        return (
            (self.pixel_format == PixelFormat.P4 and self.palette.size < 16) or
            (self.pixel_format == PixelFormat.P8 and self.palette.size < 256)
        )


CsHca = DataclassStruct(Hca)
