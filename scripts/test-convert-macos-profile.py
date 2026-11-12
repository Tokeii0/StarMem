"""验证 macOS 符号转换拒绝执行代码、重复输入与冲突符号。"""
import importlib.util
import hashlib
import tempfile
import unittest
import zipfile
import sys
from pathlib import Path

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('mac_profile_converter', Path(__file__).with_name('convert-macos-profile.py'))
converter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(converter)
BANNER = 'Darwin Kernel Version 15.6.0: Thu Jun 23 18:25:34 PDT 2016; root:xnu-3248.60.10~1/RELEASE_X86_64'

class ConversionTests(unittest.TestCase):
    def create(self, folder, source, symbols="00000000 00000000 ffffff8000200000 '_version'\n"):
        p = Path(folder) / 'profile.zip'
        with zipfile.ZipFile(p, 'w') as z:
            z.writestr('profile.vtypes', source)
            z.writestr('profile.symbol.dsymutil', symbols)
        return p

    def test_py2_literals_are_data_and_keep_64_bit_values(self):
        with tempfile.TemporaryDirectory() as folder:
            p = self.create(folder, "mac_types={'proc':[0x20L,{'p_pid':[0x10L,['int']]}]}\nmac_gvars={}\n")
            r = converter.convert(p, BANNER)
            self.assertEqual(r['symbols']['_version'], 0xffffff8000200000)
            self.assertEqual(r['types']['proc'][0], 32)
            self.assertEqual(r['expected_banner'], BANNER)
            self.assertEqual(r['source']['sha256'], hashlib.sha256(p.read_bytes()).hexdigest())

    def test_rejects_code_duplicate_assignment_and_symbol_conflict(self):
        for source in ["mac_types=__import__('os').getcwd()", "import os\nmac_types={}", "mac_types={}\nmac_types={}"]:
            with tempfile.TemporaryDirectory() as folder:
                with self.assertRaises(ValueError): converter.convert(self.create(folder, source), BANNER)
        with tempfile.TemporaryDirectory() as folder:
            symbols = "00000000 ffffff8000200000 '_version'\n00000000 ffffff8000300000 '_version'\n"
            with self.assertRaises(ValueError): converter.convert(self.create(folder, 'mac_types={}', symbols), BANNER)

    def test_long_suffix_in_strings_is_not_modified(self):
        with tempfile.TemporaryDirectory() as folder:
            p = self.create(folder, "mac_types={'0x10L':[0X20L,{'field':[0L,['string','1L']]}]}\n")
            self.assertEqual(converter.convert(p, BANNER)['types']['0x10L'][1]['field'][1], ['string','1L'])

if __name__ == '__main__': unittest.main()
