# pyright: reportPrivateUsage=false

'''
Unit test - besta_tools.hcatool.lzw
'''

from io import BytesIO

from pytest import raises

from besta_tools.common.utils import div_round_up
from besta_tools.hcatool.lzw import BitstreamReader, BitstreamWriter, CodePoint, CodePointInfo, CodePointKind, decode_bitstream, encode_bitstream


def LIT(point: int | bytes) -> CodePoint:
    if isinstance(point, bytes):
        point = point[0]
    return CodePointInfo(CodePointKind.LIT, point).as_code()


def CC() -> CodePoint:
    return CodePointInfo(CodePointKind.CC, 0).as_code()


def EOI() -> CodePoint:
    return CodePointInfo(CodePointKind.EOI, 0).as_code()


def DIC(point: int) -> CodePoint:
    return CodePointInfo(CodePointKind.DIC, point).as_code()


def naive_stream_builder_9b(a: list[CodePoint]) -> bytes:
    '''
    Emit 9-bit streams without automatic width change.
    '''
    buf = 0
    for code in reversed(a):
        buf <<= 9
        buf |= code
    return buf.to_bytes(div_round_up(len(a) * 9, 8), 'little')

TEST_CODE_SIMPLE = [
    LIT(1),
    EOI(),
]

TEST_CODE_RESET = [
    LIT(1),
    DIC(0),
    CC(),
    LIT(2),
    DIC(0),
    EOI(),
    LIT(0xfe),
    EOI(),
]

# Taken from python-lzw with slight modification
TEST_GABBA = [
    LIT(b'g'),  #
    LIT(b'a'),  # DIC(0) = b'ga'
    LIT(b'b'),  # DIC(1) = b'ab'
    LIT(b'b'),  # DIC(2) = b'bb'
    LIT(b'a'),  # DIC(3) = b'ba'
    LIT(b' '),  # DIC(4) = b'a '
    DIC(0x0),   # DIC(5) = b' g'
    DIC(0x2),   # DIC(6) = b'gab'
    DIC(0x4),   # DIC(7) = b'bba'
    LIT(b'y'),  # DIC(8) = b'a y'
    LIT(b'o'),  # DIC(9) = b'yo'
    DIC(0x5),   # DIC(10) = b'o '
    DIC(0x1),   # DIC(11) = b' ga'
    DIC(0x3),   # DIC(12) = b'abb'
    EOI(),            #
]

TEST_GABBA_BYTES = b'gabba gabba yo gabba'


def test_read_bits_simple() -> None:
    '''
    Should read bits.
    '''
    r = BytesIO(bytes((0b01110101,)))
    a = BitstreamReader(r)
    assert a._read_bits(1) == 0b1
    assert a._read_bits(3) == 0b010
    assert a._read_bits(3) == 0b111
    assert a._read_bits(1) == 0b0


def test_read_bits_out_of_bounds() -> None:
    '''
    Should throw EOFError when reaching EOF prematurely.
    '''
    r = BytesIO(bytes(1))
    a = BitstreamReader(r)
    with raises(EOFError, match='EOF reached before EOI code.'):
        _ = a._read_bits(9)


def test_read_bits_out_of_limit() -> None:
    '''
    Should throw EOFError in case the read limit is being exceeded.
    '''
    r = BytesIO(bytes(16))
    a = BitstreamReader(r, read_limit=1)
    with raises(EOFError, match='Read limit exceeded before EOI code.'):
        _ = a._read_bits(9)


def test_read_bits_across_buffer() -> None:
    '''
    Should read bits across buffer without corruption.
    '''
    r = BytesIO(b'\x00' * 4095 + bytes((0b10101000, 0b11001101, 0b11111111)))
    a = BitstreamReader(r)
    _ = a._read_bits(4095 * 8 + 3)
    assert a._read_bits(13) == 0b1100110110101


def test_bitstream_read_simple() -> None:
    '''
    Should match exactly as the sample.
    '''
    bitstream = naive_stream_builder_9b(TEST_CODE_SIMPLE)
    a = BitstreamReader(BytesIO(bitstream))
    assert list(a) == TEST_CODE_SIMPLE


def test_bitstream_read_reset() -> None:
    '''
    Should reset the code count when reached CC.
    '''
    bitstream = naive_stream_builder_9b(TEST_CODE_RESET)
    a = BitstreamReader(BytesIO(bitstream))
    next(a)
    assert a.code_count == 0x102
    next(a)
    assert a.code_count == 0x103
    next(a)
    assert a.code_count == 0x101
    next(a)
    assert a.code_count == 0x102


def test_bitstream_read_eoi() -> None:
    '''
    Should stop parsing at EOI.
    '''
    bitstream = naive_stream_builder_9b(TEST_CODE_RESET)
    a = BitstreamReader(BytesIO(bitstream))
    assert list(a) == TEST_CODE_RESET[:6]
    assert a.code_count == 0x101


def test_bitstream_write_bits() -> None:
    '''
    Should write bits.
    '''
    w = BytesIO()
    a = BitstreamWriter(w)
    a._write_bits(0b1, 1)
    a._write_bits(0b010, 3)
    a._write_bits(0b111, 3)
    a._write_bits(0b0, 1)
    a._rpad()
    buf = w.getvalue()
    assert len(buf) == 1
    assert buf[0] == 0b01110101


def test_write_bits_across_buffer() -> None:
    '''
    Should write bits across buffer without corruption.
    '''
    w = BytesIO()
    a = BitstreamWriter(w)
    a._write_bits(0, 4095 * 8 + 3)
    # Should truncate the 9 MSBs
    a._write_bits(0b111111111100110110101, 12)
    a._rpad()
    buf = w.getvalue()
    assert buf == b'\x00' * 4095 + bytes((0b10101000, 0b01001101,))


def test_bitstream_write_simple() -> None:
    '''
    Should match the naive bitstream encoder.
    '''
    w = BytesIO()
    a = BitstreamWriter(w)
    a.extend(TEST_CODE_SIMPLE)
    assert w.getvalue() == naive_stream_builder_9b(TEST_CODE_SIMPLE)


def test_bitstream_write_reset() -> None:
    '''
    Should reset the code count after wrote down CC.
    '''
    w = BytesIO()
    a = BitstreamWriter(w)
    a.append(TEST_CODE_RESET[0])
    assert a.code_count == 0x102
    a.append(TEST_CODE_RESET[1])
    assert a.code_count == 0x103
    a.append(TEST_CODE_RESET[2])
    assert a.code_count == 0x101
    a.append(TEST_CODE_RESET[3])
    assert a.code_count == 0x102


def test_bitstream_write_eoi() -> None:
    '''
    Should right pad and flush the buffer at EOI.
    '''
    w = BytesIO()
    a = BitstreamWriter(w)
    a.extend(TEST_CODE_RESET[:6])
    assert w.getvalue() == naive_stream_builder_9b(TEST_CODE_RESET[:6])
    assert a.code_count == 0x101


def test_decoder_simple() -> None:
    '''
    Should produce the same bytes as the sample.
    '''
    assert b''.join(decode_bitstream(TEST_GABBA)) == TEST_GABBA_BYTES


def test_decoder_simple_inspect_dict() -> None:
    '''
    The phrases in the dictionary should match the sample.
    '''
    test = TEST_GABBA[:-1]
    real_code_size = len(test)
    # Inject code to read out the dict values populated above.
    test.extend(DIC(p) for p in range(real_code_size - 1))
    decoder = decode_bitstream(test)
    for _ in range(real_code_size):
        _ = next(decoder)
    dict_inspect = tuple(next(decoder) for _ in range(real_code_size - 1))
    assert dict_inspect == (
        b'ga',
        b'ab',
        b'bb',
        b'ba',
        b'a ',
        b' g',
        b'gab',
        b'bba',
        b'a y',
        b'yo',
        b'o ',
        b' ga',
        b'abb',
    )


def test_encoder_simple() -> None:
    '''
    Should produce the same code list as the sample.
    '''
    assert list(encode_bitstream([TEST_GABBA_BYTES])) == TEST_GABBA


def test_encdec_loopback() -> None:
    '''
    Short loopback test. Should pass.
    '''
    text = b'can you can a can as a canner can can a can'
    enc = encode_bitstream([text])
    dec = decode_bitstream(enc)
    assert b''.join(dec) == text
