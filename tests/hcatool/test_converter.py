# pyright: reportPrivateUsage=false


import numpy as np
from numpy.testing import assert_array_equal

from besta_tools.hcatool.converter import pack_4b, unpack_4b


PACK_TEST_IN = np.array([0x55, 0xaa, 0x12, 0x34], dtype=np.uint8)
PACK_TEST_OUT = np.array([0x5, 0x5, 0xa, 0xa, 0x1, 0x2, 0x3, 0x4], dtype=np.uint8)


def test_pack_4b() -> None:
    assert_array_equal(pack_4b(PACK_TEST_OUT), PACK_TEST_IN)


def test_unpack_4b() -> None:
    assert_array_equal(unpack_4b(PACK_TEST_IN), PACK_TEST_OUT)
