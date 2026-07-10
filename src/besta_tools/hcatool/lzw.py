'''
Besta-flavored LZW.

This is basically an implementation of the GIF variant of LZW with input bit
width hardcoded to 8, because that's what Besta uses for their encoder.

The API is somewhat inspired by python-lzw.
'''

from collections.abc import Generator, Iterable, Iterator
from dataclasses import dataclass
from enum import Enum, auto
from io import BufferedIOBase
from itertools import chain
from logging import getLogger
from typing import Final, Self, override

from ..common.utils import div_round_up


# BufferedReader/Writer is not compatible with most other IO objects that are
# based on BufferedIOBase. Therefore we now just use BufferedIOBase instead.
type BufferedReadable = BufferedIOBase
type BufferedWritable = BufferedIOBase


logger = getLogger('besta_tools.hcatool.lzw')


IO_BLOCK_SIZE: Final = 4096
IO_BLOCK_SIZE_BITS: Final = IO_BLOCK_SIZE * 8
CODE_MAX: Final = 0xfff
CODE_CC: Final = 0x100
CODE_EOI: Final = 0x101
CODE_DIC_BASE: Final = 0x102

# CODEPOINT_DIC_BASE - 1 because the first code will always be a LIT(), thus no
# write operation to the dictionary.
CODE_COUNT_RESET: Final = CODE_DIC_BASE - 1


LIT_TAB: Final = {p: bytes((p,)) for p in range(256)}


type CodePoint = int


class CodePointKind(Enum):
    LIT = auto()
    CC = auto()
    EOI = auto()
    DIC = auto()


def is_valid(code: CodePoint) -> bool:
    return code < 0 or code > CODE_MAX


def is_lit(code: CodePoint) -> bool:
    return code < CODE_CC


def is_cc(code: CodePoint) -> bool:
    return code == CODE_CC


def is_eoi(code: CodePoint) -> bool:
    return code == CODE_EOI


def is_dic(code: CodePoint) -> bool:
    return code >= CODE_DIC_BASE and code < CODE_MAX


@dataclass
class CodePointInfo:
    '''
    Parse a codepoint and format it as a human-readable string.

    For inspection only. While this can be used to manipulate codepoints,
    it is unoptimized and can cause significant slowdown in a hot path.
    Therefore do not use it in subroutines that do the actual encode and
    decode operations.
    '''
    kind: CodePointKind
    point: int

    def __post_init__(self) -> None:
        if self.point < 0:
            raise ValueError('Point cannot be negative.')
        if self.kind == CodePointKind.LIT and self.point > 0xff:
            raise ValueError('LIT point cannot exceed 0xff')
        elif self.kind == CodePointKind.DIC and \
                self.point + CODE_DIC_BASE > CODE_MAX:
            raise ValueError(
                'DIC point cannot exceed ' +
                f'0x{CODE_MAX - CODE_DIC_BASE:x}'
            )
        assert self.as_code() <= CODE_MAX

    @override
    def __str__(self) -> str:
        if self.kind in (CodePointKind.CC, CodePointKind.EOI):
            return f'[{self.as_code():03x}] {self.kind.name}'
        else:
            return f'[{self.as_code():03x}] {self.kind.name}(0x{self.point:x})'

    def as_code(self) -> CodePoint:
        if self.kind == CodePointKind.CC:
            return CODE_CC
        elif self.kind == CodePointKind.EOI:
            return CODE_EOI
        elif self.kind == CodePointKind.LIT:
            return self.point
        else:
            return self.point + CODE_DIC_BASE

    @classmethod
    def from_code(cls, code: CodePoint) -> Self:
        if code < 0 or code > CODE_MAX:
            raise ValueError(f'Invalid codepoint {code}')

        if is_lit(code):
            return cls(kind=CodePointKind.LIT, point=code)
        elif is_cc(code):
            return cls(kind=CodePointKind.CC, point=0)
        elif is_eoi(code):
            return cls(kind=CodePointKind.EOI, point=0)
        else:
            return cls(kind=CodePointKind.DIC, point=code - CODE_DIC_BASE)


@dataclass
class Stats:
    num_input_units: int = 0
    num_output_units: int = 0
    num_streams: int = 0


class Decoder(Iterator[bytes]):
    '''
    Proxy to the iterator interface of decode_bitstream, that also allows easy
    statistics access.
    '''
    _stats: Stats
    _bitstream: Iterable[CodePoint]
    _it: Iterator[bytes]

    @property
    def num_code_read(self) -> int:
        return self._stats.num_input_units

    @property
    def num_bytes_written(self) -> int:
        return self._stats.num_output_units

    @property
    def num_streams(self) -> int:
        return self._stats.num_streams

    @override
    def __str__(self) -> str:
        return (
            self.__class__.__name__ +
            f'(num_code_read={self.num_code_read}, ' +
            f'num_bytes_written={self.num_bytes_written}, ' +
            f'num_streams={self.num_streams})'
        )

    def __init__(self, bitstream: Iterable[CodePoint]) -> None:
        self._bitstream = bitstream
        self._stats = Stats()

        self._it = decode_bitstream(self._bitstream, self._stats)

    @override
    def __next__(self) -> bytes:
        return next(self._it)


class Encoder(Iterator[CodePoint]):
    '''
    Proxy to the iterator interface of encode_bitstream, that also allows easy
    statistics access.
    '''
    _stats: Stats
    _bytestream: Iterable[bytes]
    _it: Iterator[CodePoint]

    @property
    def num_bytes_read(self) -> int:
        return self._stats.num_input_units

    @property
    def num_code_written(self) -> int:
        return self._stats.num_output_units

    @property
    def num_streams(self) -> int:
        return self._stats.num_streams

    @override
    def __str__(self) -> str:
        return (
            self.__class__.__name__ +
            f'(num_bytes_read={self.num_bytes_read}, ' +
            f'num_code_written={self.num_code_written}, ' +
            f'num_streams={self.num_streams})'
        )

    def __init__(self, bytestream: Iterable[bytes]) -> None:
        self._bytestream = bytestream
        self._stats = Stats()

        self._it = encode_bitstream(self._bytestream, self._stats)

    @override
    def __next__(self) -> CodePoint:
        return next(self._it)


class BitstreamReader(Iterator[CodePoint]):
    '''
    Read and parse a LZW bitstream from a Buffered IO object.
    '''
    _r: BufferedReadable
    _buffer: int
    _bitlen: int
    _read_limit: int | None
    _code_count: int
    _shutdown: bool
    _read_count: int

    def __init__(self, reader: BufferedReadable, read_limit: int | None = None) -> None:
        self._r = reader
        self._buffer = 0
        self._bitlen = 0
        self._read_limit = read_limit
        self._code_count = CODE_COUNT_RESET
        self._shutdown = False
        self._read_count = 0

    @property
    def code_count(self) -> int:
        return self._code_count

    @property
    def read_count(self) -> int:
        return self._read_count - self._bitlen

    def inspect(self) -> Generator[CodePointInfo]:
        for code in self:
            yield CodePointInfo.from_code(code)

    def _read_bits(self, count: int) -> int:
        code = 0
        code_offset = 0
        code_width = count

        while code_offset != code_width:
            assert code_offset < code_width
            if self._bitlen == 0:
                if self._read_limit is not None:
                    read_size = min(IO_BLOCK_SIZE, self._read_limit)
                    if read_size == 0:
                        raise EOFError('Read limit exceeded before EOI code.')
                    self._read_limit -= read_size
                else:
                    read_size = IO_BLOCK_SIZE

                new_data = self._r.read(read_size)
                if len(new_data) == 0:
                    raise EOFError('EOF reached before EOI code.')
                self._read_count += len(new_data) * 8

                self._buffer = int.from_bytes(new_data, 'little')
                self._bitlen = len(new_data) * 8

            pop_amount = min(code_width - code_offset, self._bitlen)
            code |= (self._buffer & ((1 << pop_amount) - 1)) << code_offset

            self._bitlen -= pop_amount
            self._buffer >>= pop_amount
            code_offset += pop_amount

        return code

    @override
    def __next__(self) -> CodePoint:
        if self._shutdown:
            raise StopIteration()

        code = self._read_bits(self._code_count.bit_length())

        if code == CODE_CC:
            self._code_count = CODE_COUNT_RESET
        elif code == CODE_EOI:
            logger.info('EOI code seen. Stop decoding.')
            self._code_count = CODE_COUNT_RESET
            self._shutdown = True
        elif self._code_count < CODE_MAX:
            # Make sure code count does not go above CODEPOINT_MAX, but also
            # do not produce an error when it tries to, to support deferred CC.
            self._code_count += 1

        assert self._code_count <= CODE_MAX, 'Codepoint counter overflow.'

        return code

    def decode(self) -> Decoder:
        '''
        Decode from the reader object passed to this decoder.

        Returns the Decoder iterator instance that the caller can then
        enumerate over.
        '''
        return Decoder(self)


class BitstreamWriter:
    '''
    Serialize and write LZW code sequence to a Buffered IO object.
    '''
    _w: BufferedWritable
    _buffer: int
    _bitlen: int
    _code_count: int
    _write_count: int

    def __init__(self, writer: BufferedWritable) -> None:
        self._w = writer
        self._buffer = 0
        self._bitlen = 0
        self._code_count = CODE_COUNT_RESET
        self._write_count = 0

    @property
    def code_count(self) -> int:
        return self._code_count

    @property
    def write_count(self) -> int:
        '''
        Number of bits written (not padded to bytes).
        '''
        return self._write_count

    def _rpad(self) -> None:
        '''
        Right pad the leftover bits into whole bytes and write to the
        underlying writer.
        '''
        self._write_count += self._bitlen
        write_size = div_round_up(self._bitlen, 8)
        self._w.write(self._buffer.to_bytes(write_size, 'little'))
        self._w.flush()
        self._buffer = 0
        self._bitlen = 0

    def _write_bits(self, source: int, width: int) -> None:
        offset = 0
        while offset != width:
            assert offset < width

            remaining_space = IO_BLOCK_SIZE_BITS - self._bitlen
            push_amount = min(remaining_space, width - offset)
            source_mask = (1 << push_amount) - 1

            self._buffer |= (source & source_mask) << self._bitlen

            self._bitlen += push_amount
            source >>= push_amount
            offset += push_amount

            assert self._bitlen <= IO_BLOCK_SIZE_BITS

            if self._bitlen == IO_BLOCK_SIZE_BITS:
                self._write_count += IO_BLOCK_SIZE_BITS
                self._w.write(self._buffer.to_bytes(IO_BLOCK_SIZE, 'little'))
                self._buffer = 0
                self._bitlen = 0

    def append(self, code: CodePoint) -> None:
        '''
        Append a single code point to the stream. Expected code size is
        automatically adjusted as code points are being inserted, and control
        code points i.e. CC or EOI are automatically handled.
        '''
        code_width = self._code_count.bit_length()
        self._write_bits(code, code_width)

        if code == CODE_CC:
            self._code_count = CODE_COUNT_RESET
        elif code == CODE_EOI:
            self._code_count = CODE_COUNT_RESET
            self._rpad()
        elif self._code_count < CODE_MAX:
            self._code_count += 1

        assert self._code_count <= CODE_MAX, 'Codepoint counter overflow.'

    def extend(self, code: Iterable[CodePoint]) -> None:
        '''
        Append multiple code points to the stream.
        '''
        for c in code:
            self.append(c)

    def encode(self, input_data: Iterable[bytes]) -> Encoder:
        '''
        Encode a Sequence or Iterator of bytes and write the result bitstream
        to the IO object.

        Returns the finished Encoder iterator instance to the caller.
        '''
        enc = Encoder(input_data)
        self.extend(enc)
        return enc


def decode_bitstream(bitstream: Iterable[CodePoint], stats: Stats | None = None) -> Generator[bytes]:
    '''
    Decode a Sequence or an Iterable of LZW code points into phrases.
    '''
    prefix: bytes = b''
    dic: dict[int, bytes] = {}
    # Cache literals on another table so we can execute CC without regenerating the doorstop bytes
    lit = {p: bytes((p,)) for p in range(256)}

    st = 0
    ni = 0
    no = 0

    def _next_code() -> int:
        return len(dic) + CODE_DIC_BASE

    for code in bitstream:
        expanded: bytes
        assert _next_code() not in dic
        if is_cc(code) or is_eoi(code):
            st += 1
            dic.clear()
            expanded = b''
        elif len(prefix) == 0:
            if not is_lit(code):
                raise ValueError(
                    'Bad bitstream: first code is neither a control nor a LIT.'
                )
            expanded = lit[code]
        elif is_lit(code):
            # Literal counts as a dictionary hit.
            expanded = lit[code]
            prefix = prefix + expanded
            dic[_next_code()] = prefix
        elif is_dic(code):
            entry = dic.get(code)
            if entry is not None:
                # Dictionary hit.
                expanded = entry
                prefix = prefix + entry[0:1]
                dic[_next_code()] = prefix
            else:
                # Dictionary miss. Generate it on the fly.
                if _next_code() != code:
                    logger.warning(
                        'Bogus code %s: Attempting to create a dictionary ' +
                        'entry that is not immediately needed (expecting %s).',
                        CodePointInfo.from_code(code),
                        CodePointInfo.from_code(_next_code()),
                    )
                prefix = prefix + prefix[0:1]
                expanded = prefix
                dic[_next_code()] = prefix
        else:
            raise RuntimeError('Invalid code found in input stream.')

        no += len(expanded)
        ni += 1

        yield expanded
        prefix = expanded
    
    if stats is not None:
        stats.num_input_units = ni
        stats.num_output_units = no
        stats.num_streams = st


def encode_bitstream(bytestream: Iterable[bytes], stats: Stats | None = None) -> Generator[CodePoint]:
    '''
    Greedily find the longest phrases in a Sequence or an Iterable of bytes and
    encode them into a series of LZW code points.
    '''

    prefix: bytes
    dic: dict[bytes, int] = {}
    lit = {p: bytes((p,)) for p in range(256)}

    st = 0
    ni = 0
    no = 0

    def _next_code() -> int:
        return len(dic) + CODE_DIC_BASE

    byteit = chain.from_iterable(bytestream)
    try:
        prefix = lit[next(byteit)]
        ni += 1
    except StopIteration:
        if stats is not None:
            stats.num_output_units = 1
        yield CODE_EOI
        return

    for byte in byteit:
        ni += 1

        lit_byte = lit[byte]
        expanded = prefix + lit_byte

        code = dic.get(expanded)
        if code is not None:
            # Try to match more.
            prefix = expanded
        else:
            # No more match, yield the code we currently have and remember the
            # new expanded phrase as a code (if we still got capacity).
            no += 1
            yield prefix[0] if len(prefix) == 1 else dic[prefix]
            # Besta hcatool clears the code one step ahead. Mimic this
            # behavior.
            if _next_code() >= CODE_MAX - 1:
                no += 1
                st += 1
                dic.clear()
                prefix = b''
                yield CODE_CC
            else:
                dic[expanded] = _next_code()
            prefix = lit_byte

    # Finish off
    no += 1 if len(prefix) == 0 else 2
    st += 1

    if stats is not None:
        stats.num_input_units = ni
        stats.num_output_units = no
        stats.num_streams = st

    if len(prefix) != 0:
        yield prefix[0] if len(prefix) == 1 else dic[prefix]
    yield CODE_EOI


def compress_stream(bitstream: BufferedWritable, datastream: BufferedReadable, read_size: int | None = None) -> None:
    def _chunk_reader(s: BufferedReadable, read_size: int | None):
        while True:
            block_size = min(read_size, 1048576) if read_size is not None else 1048576
            buf = s.read(block_size)
            if len(buf) == 0:
                break
            yield buf

    BitstreamWriter(bitstream).extend(encode_bitstream(_chunk_reader(datastream, read_size)))


def decompress_stream(datastream: BufferedWritable, bitstream: BufferedReadable, read_size: int | None = None) -> None:
    for expanded in BitstreamReader(bitstream, read_limit=read_size).decode():
        datastream.write(expanded)
