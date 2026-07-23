# pyright: reportPrivateUsage=false

from typing import Final

from pytest_mock import MockerFixture

import numpy as np
from numpy.testing import assert_array_equal

from besta_tools.hcatool.converter import pack_4b, try_compress, unpack_4b, _clip_rgb24_to_rgb12


PACK_TEST_IN = np.array([0x55, 0xaa, 0x12, 0x34], dtype=np.uint8)
PACK_TEST_IN_2D = np.array([[0x55, 0xaa], [0x12, 0x34]], dtype=np.uint8)
PACK_TEST_OUT = np.array([0x5, 0x5, 0xa, 0xa, 0x1, 0x2, 0x3, 0x4], dtype=np.uint8)
PACK_TEST_OUT_2D = np.array([[0x5, 0x5, 0xa, 0xa], [0x1, 0x2, 0x3, 0x4]], dtype=np.uint8)

COMPRESSED: Final = b'compressed'
COMPRESSED_LONG: Final = b'compressedbutitsloooooooooooooong'
UNCOMPRESSED: Final = b'uncompressed'


def _dual12(color0: int, color1: int) -> tuple[int, int, int]:
    b0, b1, b2 = (color0 | (color1 << 12)).to_bytes(3, 'little')
    return (b0, b1, b2)


def test_pack_4b() -> None:
    assert_array_equal(pack_4b(PACK_TEST_OUT), PACK_TEST_IN)


def test_unpack_4b() -> None:
    assert_array_equal(unpack_4b(PACK_TEST_IN), PACK_TEST_OUT)


def test_pack_4b_2d() -> None:
    assert_array_equal(pack_4b(PACK_TEST_OUT_2D), PACK_TEST_IN_2D)


def test_unpack_4b_2d() -> None:
    assert_array_equal(unpack_4b(PACK_TEST_IN_2D), PACK_TEST_OUT_2D)


def test_try_compress_force_compression(mocker: MockerFixture) -> None:
    p = mocker.patch('besta_tools.hcatool.converter._compress')
    p.return_value = COMPRESSED_LONG
    compressed, result = try_compress(UNCOMPRESSED, compress=True)
    p.assert_called_once_with(UNCOMPRESSED)
    assert compressed
    assert result == COMPRESSED_LONG


def test_try_compress_disable_compression(mocker: MockerFixture) -> None:
    p = mocker.patch('besta_tools.hcatool.converter._compress')
    p.return_value = COMPRESSED_LONG
    compressed, result = try_compress(UNCOMPRESSED, compress=False)
    p.assert_not_called()
    assert not compressed
    assert result == UNCOMPRESSED


def test_try_compress_auto_compression_win(mocker: MockerFixture) -> None:
    p = mocker.patch('besta_tools.hcatool.converter._compress')
    p.return_value = COMPRESSED
    compressed, result = try_compress(UNCOMPRESSED)
    p.assert_called_once_with(UNCOMPRESSED)
    assert compressed
    assert result == COMPRESSED


def test_try_compress_auto_compression_lose(mocker: MockerFixture) -> None:
    p = mocker.patch('besta_tools.hcatool.converter._compress')
    p.return_value = COMPRESSED_LONG
    compressed, result = try_compress(UNCOMPRESSED)
    p.assert_called_once_with(UNCOMPRESSED)
    assert not compressed
    assert result == UNCOMPRESSED


def test_clip_rgb24_to_rgb12() -> None:
    inp = np.array([
        [[0x55, 0x55, 0x55], [0xaa, 0xaa, 0xaa], [0x11, 0x22, 0x33], [0x99, 0xaa, 0xbb]],
        [[0x00, 0x00, 0x00], [0xff, 0xff, 0xff], [0xaa, 0xaa, 0xaa], [0x55, 0x55, 0x55]],
        [[0x55, 0x55, 0x55], [0xaa, 0xaa, 0xaa], [0x11, 0x22, 0x33], [0x99, 0xaa, 0xbb]],
        [[0x00, 0x00, 0x00], [0xff, 0xff, 0xff], [0xaa, 0xaa, 0xaa], [0x55, 0x55, 0x55]],
    ])
    outp = _clip_rgb24_to_rgb12(inp)
    assert_array_equal(outp, np.array([
        [_dual12(0x555, 0xaaa), _dual12(0x321, 0xba9)],
        [_dual12(0x000, 0xfff), _dual12(0xaaa, 0x555)],
        [_dual12(0x555, 0xaaa), _dual12(0x321, 0xba9)],
        [_dual12(0x000, 0xfff), _dual12(0xaaa, 0x555)],
    ]))
