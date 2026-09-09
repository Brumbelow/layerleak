import importlib.util
from pathlib import Path
import struct
import unittest


class ContainerPlatformTests(unittest.TestCase):
    def setUp(self):
        script = Path(__file__).parents[1] / 'verify-container-platform.py'
        self.assertTrue(script.exists(), 'container architecture verifier is not implemented')
        spec = importlib.util.spec_from_file_location('container_platform', script)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    @staticmethod
    def header(machine, byte_order=1, elf_class=2):
        data = bytearray(64)
        data[:6] = b'\x7fELF' + bytes([elf_class, byte_order])
        struct.pack_into('<H', data, 18, machine)
        return bytes(data)

    def test_matching_64_bit_executables_pass(self):
        self.module.verify_elf_header(self.header(62), 'amd64')
        self.module.verify_elf_header(self.header(183), 'arm64')

    def test_mislabeled_arm_image_executable_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'machine 62.*arm64'):
            self.module.verify_elf_header(self.header(62), 'arm64')

    def test_invalid_executable_headers_are_rejected(self):
        for header in (b'', b'not an executable', self.header(183, byte_order=2),
                       self.header(183, elf_class=1)):
            with self.subTest(header=header):
                with self.assertRaises(ValueError):
                    self.module.verify_elf_header(header, 'arm64')


if __name__ == '__main__':
    unittest.main()
