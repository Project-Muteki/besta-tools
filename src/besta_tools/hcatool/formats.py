'''
HCA constructs and helper functions.

The construct part is more or less a straight port of the hca.hexpat pattern,
with many advanced features of construct being used to reduce post-parser code
complexity, while maintaining the flexibility of the resulting objects.
'''

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import islice
from typing import TYPE_CHECKING, Self, cast, override

from construct import Array, Bytes, Check, Computed, Const, Default, IfThenElse, Int16ul, Int32ul, Int8ul, Pass, Rebuild, Switch, len_, this
from construct_typed import DataclassMixin, DataclassStruct, csfield

from ..common.tenum_patched import EnumBase, TEnum


if TYPE_CHECKING:
    from construct import Context


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

    @abstractmethod
    def to_rgb12(self) -> list[int]:
        raise NotImplementedError()

    def to_rgb(self) -> list[tuple[float, float, float]]:
        return list(
            (
                (c & 0xf) / 0xf,
                ((c >> 4) & 0xf) / 0xf,
                ((c >> 8) & 0xf) / 0xf
            ) for c in self.to_rgb12()
        )


# We intentionally do not use construct to rebuild the palette so we can get
# maximum flexibility on its content (like exploring the possibility of more
# than 16/256 colors on indexed image by abusing its unique vectored palette
# format).
@dataclass
class HcaPalette8Bpp(DataclassMixin, HcaPaletteBase):
    _len: int | None = csfield(cast('Computed[int]', Computed(this._.palette_size)))
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


CsHcaPalette8Bpp = DataclassStruct(HcaPalette8Bpp)


@dataclass
class HcaPalette4Bpp(DataclassMixin, HcaPaletteBase):
    color: list[int] = csfield(Array(16 * 16, Int32ul))

    @property
    @override
    def size(self) -> int:
        return 16

    @classmethod
    @override
    def from_rgb12(cls, rgb12s: Sequence[int]) -> Self:
        if len(rgb12s) > 16:
            raise ValueError('Palette must have no more than 16 entries.')
        sparse = dict(enumerate(rgb12s))

        return cls(color=[sparse.get(x, 0) << 12 | sparse.get(y, 0) for x in range(16) for y in range(16)])

    @override
    def to_rgb12(self) -> list[int]:
        return [(c >> 12) & 0xfff for c in islice(self.color, 16)]


CsHcaPalette4Bpp = DataclassStruct(HcaPalette4Bpp)


@dataclass
class HcaPaletteDummy(DataclassMixin, HcaPaletteBase):
    '''
    Empty palette class so we can mount our stuff onto it.
    '''
    _color: None = csfield(Pass)

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
    _sbz_0x4: int | None = csfield(Const(0, Int32ul))
    _sbz_0x8: int | None = csfield(Const(0, Int8ul))
    _padding: bytes | None = csfield(Default(Bytes(3), b'\x00\x00\x00'))


CsHcaFrameHeader = DataclassStruct(HcaFrameHeader)


@dataclass
class HcaFrameContainer(DataclassMixin):
    _len: int = csfield(IfThenElse(
        this._index == this._.nframes - 1,
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


@dataclass
class Hca(DataclassMixin):
    magic: bytes = csfield(Const(b'HCA'))
    pixel_format: PixelFormat = csfield(CsPixelFormat)
    height: int = csfield(Int16ul)
    width: int = csfield(Int16ul)
    nframes: int = csfield(Rebuild(Int8ul, len_(this.frames)))
    # TODO: Somehow type of Switch didn't get automatically detected.
    palette_size: int = csfield(cast(
        'Switch[int, int]',
        Switch(this.pixel_format, {
            PixelFormat.P4: Rebuild(Int8ul, 16),
            PixelFormat.P8: Rebuild(Int8ul, len_(this.palette.color_even)),
            PixelFormat.RGB12: Const(0, Int8ul),
        })
    ))
    _nframes2: int | None = csfield(Rebuild(Int8ul, len_(this.frames)))
    _check_nframes_match: None = csfield(Check(this.nframes == this._nframes2))
    transparent_color_index: int = csfield(Int8ul)
    palette: HcaPaletteBase = csfield(cast(
        'Switch[HcaPaletteBase, HcaPaletteBase]',
        Switch(this.pixel_format, {
            PixelFormat.P4: CsHcaPalette4Bpp,
            PixelFormat.P8: CsHcaPalette8Bpp,
            PixelFormat.RGB12: CsHcaPaletteDummy,
        })
    ))
    _data_size: int | None = csfield(Rebuild(Int32ul, rebuild_hca_data_size))
    _frame_offsets: list[int] | None = csfield(Rebuild(Array(this.nframes, Int32ul), rebuild_hca_frame_offsets))
    frames: list[HcaFrameContainer] = csfield(Array(this.nframes, CsHcaFrameContainer))


CsHca = DataclassStruct(Hca)
