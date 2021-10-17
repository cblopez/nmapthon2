import unittest
import sys
import os

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from nmapthon2.results import NmapScanResult
from nmapthon2.scanner import NmapScanner
from nmapthon2.ports import tcp, udp, top_ports
from nmapthon2.exceptions import InvalidArgumentError, InvalidPortError, NmapScanError

class TestScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = NmapScanner()

    def test_targets_raw(self):
        self.scanner.scan('localhost', dry_run=True)
    
    def test_targets_multi(self):
        self.scanner.scan('localhost scanme.nmap.org 10.10.10.2', dry_run=True)

    def test_targets_list(self):
        self.scanner.scan(['localhost', '10.10.10.10'], dry_run=True)

    def test_targets_tuple(self):
        self.scanner.scan(('localhost', '10.10.10.10'), dry_run=True)
    
    def test_ports_string(self):
        self.scanner.scan('localhost', ports='22', dry_run=True)
    
    def test_ports_int(self):
        self.scanner.scan('localhost', ports=80, dry_run=True)
    
    def test_ports_tcp(self):
        self.scanner.scan('localhost', ports=tcp(80), dry_run=True)
    
    def test_ports_udp(self):
        self.scanner.scan('localhost', ports=udp('90'), dry_run=True)
    
    def test_ports_top(self):
        self.scanner.scan('localhost', ports=top_ports(1000), dry_run=True)
    
    def test_ports_tcp_udp(self):
        self.scanner.scan('localhost', ports=tcp([22, 80]).udp('63'), dry_run=True)
    
    def test_ports_udp_tcp(self):
        self.scanner.scan('localhost', ports=udp('63').tcp([22, 80]), dry_run=True)
    
    def test_invalid_ports(self):
        with self.assertRaises(InvalidPortError):
            self.scanner.scan('localhost', ports=udp('69999'), dry_run=True)
    
    def test_out_of_range_top_ports(self):
        with self.assertRaises(InvalidPortError):
            self.scanner.scan('localhost', ports=top_ports(69999), dry_run=True)

    def test_invalid_top_ports_with_other(self):
        with self.assertRaises(InvalidPortError):
            self.scanner.scan('localhost', ports=top_ports(100).tcp(90), dry_run=True)

    def test_invalid_other_with_top_ports(self):
        with self.assertRaises(InvalidPortError):
            self.scanner.scan('localhost', ports=udp(90).top_ports(100), dry_run=True)

    def test_valid_arguments(self):
        self.scanner.scan('localhost', arguments='-sS -T4', dry_run=True)
    
    def test_invalid_arguments(self):
        with self.assertRaises(NmapScanError):
            self.scanner.scan('localhost', arguments='-s9 -T4')

if __name__ == '__main__':
    unittest.main()