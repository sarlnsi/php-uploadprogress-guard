"""Check actual C bounds arithmetic against unbounded integer arithmetic, including wraparound."""
import ctypes
from pathlib import Path
import random
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Headroom(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        text = (ROOT / 'src/rfc1867/rfc1867_copy-7.4.c').read_text()
        function = re.search(r'static int hp_mem_room\(size_t need\)\n\{.*?\n\}', text, re.S).group()
        fixture = r'''
#include <stddef.h>
static long configured_limit;
static size_t used_memory;
#define PG(field) configured_limit
#define HP_MEM_CHUNK ((size_t)2*1024*1024)
#define HP_MEM_SLACK ((size_t)4*1024*1024)
static size_t zend_memory_usage(int real) { return used_memory; }
'''
        fixture += function + '''
int check(long limit, size_t used, size_t need) {
 configured_limit=limit; used_memory=used; return hp_mem_room(need);
}
'''
        directory = Path(cls.temp.name)
        source = directory / 'arithmetic.c'
        source.write_text(fixture)
        subprocess.run(['gcc', '-shared', '-fPIC', '-O2', '-Wall', '-Werror', str(source),
                        '-o', str(directory / 'arithmetic.so')], check=True)
        cls.library = ctypes.CDLL(str(directory / 'arithmetic.so'))
        cls.library.check.argtypes = [ctypes.c_long, ctypes.c_size_t, ctypes.c_size_t]
        cls.library.check.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def assert_matches_math(self, limit, used, need):
        chunk = 2 * 1024 * 1024
        reserve = max(limit // 8, 4 * 1024 * 1024)
        rounded = ((need + chunk - 1) // chunk) * chunk
        expected = limit <= 0 or used + rounded + 4 * 1024 * 1024 + reserve <= limit
        self.assertEqual(bool(self.library.check(limit, used, need)), expected,
                         (limit, used, need))

    def test_wraparound_is_rejected(self):
        maximum = (1 << (8 * ctypes.sizeof(ctypes.c_size_t))) - 1
        self.assert_matches_math(128 * 1024 * 1024, 2 * 1024 * 1024, maximum)
        self.assert_matches_math(128 * 1024 * 1024, maximum - 10, 16)

    def test_boundaries_and_random_inputs(self):
        rand = random.Random(20261022)
        maximum = (1 << (8 * ctypes.sizeof(ctypes.c_size_t))) - 1
        for _ in range(10000):
            limit = rand.choice([-1, 0, 16 << 20, 32 << 20, 128 << 20, (1 << 63) - 1])
            used = rand.choice([0, 2 << 20, rand.randrange(1 << 32), maximum - rand.randrange(1024)])
            need = rand.choice([0, 1, 2 << 20, rand.randrange(1 << 32), maximum - rand.randrange(1024)])
            self.assert_matches_math(limit, used, need)


if __name__ == '__main__':
    unittest.main()
