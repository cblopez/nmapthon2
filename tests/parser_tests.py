import unittest
import sys
import os 

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from nmapthon2.parser import XMLParser
from nmapthon2.results import NmapScanResult

class TestParser(unittest.TestCase):

    def setUp(self):
        self.xml_parser = XMLParser()
        self.xml_file = './assets/test.xml'
        self.result = self.xml_parser.parse_file(self.xml_file)

    def test_parse_file(self):
        self.assertIsInstance(self.xml_parser.parse_file(self.xml_file), NmapScanResult)

    def test_parse_unexistant_file(self):
        with self.assertRaises(FileNotFoundError):
            self.xml_parser.parse_file('./thisfiledoesnotexist.xml')

if __name__ == '__main__':
    unittest.main()