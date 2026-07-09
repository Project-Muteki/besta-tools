'''
Integration test - besta_tools.hcatool.lzw

VERY SLOW and it's probably not necessary to run this with every change.
'''

from hashlib import sha256
from io import SEEK_END, BufferedIOBase
import lzma
from pathlib import Path
from tempfile import TemporaryFile

from besta_tools.hcatool.lzw import *


DATA_PATH = Path(__file__).parent / 'data'


def chunk_reader(file: BufferedIOBase) -> Generator[bytes]:
    while True:
        buf = file.read(1048576)
        if len(buf) == 0:
            break
        yield buf


def loopback_test(testfile: Path) -> None:
    s = sha256()

    with lzma.open(testfile, 'rb') as f:
        for c in chunk_reader(f):
            s.update(c)

    expected_sha256 = s.digest()

    with TemporaryFile('w+b') as out:
        with lzma.open(testfile, 'rb') as f:
            w = BitstreamWriter(out)
            enc = w.encode(chunk_reader(f))
            print(enc)
            print('BitstreamEncoder wrote', w.write_count, 'bits to output.')
        
        bitstream_file_size = out.seek(0, SEEK_END)
        out.seek(0)

        print(bitstream_file_size, 'bytes in output file.')

        s = sha256()
        r = BitstreamReader(out)
        dec = r.decode()
        for expanded in dec:
            s.update(expanded)
        print(dec)
        print('BitstreamDecoder read', r.read_count, 'bits from input.')

    actual_sha256 = s.digest()

    assert expected_sha256 == actual_sha256
    assert w.write_count == r.read_count
    assert div_round_up(w.write_count, 8) == bitstream_file_size
    

def test_loopback_wikipetan() -> None:
    '''
    Simple pixel-art style image with blocky color. Realistic usage of LZW.
    '''
    loopback_test(DATA_PATH / 'wikipetan.bmp.xz')


def test_loopback_power() -> None:
    '''
    Just a noisy image. For torture testing to make sure it can handle complex
    en/decoding back-to-back.
    '''
    loopback_test(DATA_PATH / 'power.bmp.xz')
