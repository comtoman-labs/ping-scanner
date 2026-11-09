import unittest
import struct
import ping_scanner

class TestPingScannerHostname(unittest.TestCase):
    def setUp(self):
        with ping_scanner._cache_lock:
            ping_scanner._hostname_cache.clear()

    def test_hostname_unknown_ip_returns_empty(self):
        # Unknown IP not in DNS or mDNS returns ""
        name = ping_scanner.get_hostname("192.0.2.123")
        self.assertEqual(name, "")

    def test_hostname_dns_resolution(self):
        # 127.0.0.1 should resolve via DNS
        name = ping_scanner.get_hostname("127.0.0.1")
        self.assertTrue(len(name) > 0)

    def test_mdns_packet_parsing(self):
        # Synthetic packet simulating Avahi mDNS response for 250.10.16.172.in-addr.arpa
        hdr = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        ans_qname = b"\x03250\x0210\x0216\x03172\x07in-addr\x04arpa\x00"
        target_name = b"\x0eainode-desktop\x05local\x00"
        ans_rr = ans_qname + struct.pack("!HHIH", 12, 1, 120, len(target_name)) + target_name
        packet = hdr + ans_rr

        extracted = ping_scanner._extract_ptr_target(packet)
        self.assertEqual(extracted, "ainode-desktop")

    def test_mdns_query_packet_builder(self):
        query = ping_scanner._build_mdns_ptr_query("172.16.10.250")
        self.assertTrue(len(query) > 12)
        # Verify question contains 250.10.16.172.in-addr.arpa
        self.assertIn(b"in-addr", query)
        self.assertIn(b"arpa", query)
        self.assertIn(b"250", query)

if __name__ == "__main__":
    unittest.main(verbosity=2)
