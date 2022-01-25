import unittest
import requests

class TestCase(unittest.TestCase):


    def test_getheight_mainnet(self):
        response = requests.get('http://127.0.0.1:5000/grpc/mainnet/GetHeight')
        self.assertEqual('height', next(iter(response.json())))
        self.assertEqual(200, response.status_code)

    def test_getheight_testnet(self):
        response = requests.get('http://127.0.0.1:5000/grpc/testnet/GetHeight')
        self.assertEqual('height', next(iter(response.json())))
        self.assertEqual(200, response.status_code)

    def test_getstats_mainnet(self):
        response = requests.get('http://127.0.0.1:5000/grpc/mainnet/GetStats')
        self.assertEqual('nodeInfo', next(iter(response.json())))
        self.assertEqual(200, response.status_code)

    def test_getstats_testnet(self):
        response = requests.get('http://127.0.0.1:5000/grpc/testnet/GetStats')
        self.assertEqual('nodeInfo', next(iter(response.json())))
        self.assertEqual(200, response.status_code)

    def test_getbalance_mainnet(self):
        response = requests.get('http://127.0.0.1:5000/grpc/mainnet/GetBalance/Q010500ad84debb245a7cd37c1ad538e634567ae9db7e6603d5c0e4834aa628255e207ea5dcd733')
        self.assertEqual('balance', next(iter(response.json())))
        self.assertEqual(200, response.status_code)

    def test_getbalance_testnet(self):
        response = requests.get('http://127.0.0.1:5000/grpc/testnet/GetBalance/Q0104008eeaa68d90419bc8401b15882d0bcf6c9190d652923f768cac621b58d7e7c7945d7fc97f')
        self.assertEqual('balance', next(iter(response.json())))
        self.assertEqual(200, response.status_code)

    def test_getblockbynumber_mainnet(self):
        response = requests.get('http://127.0.0.1:5000/grpc/mainnet/GetBlockByNumber/1')
        self.assertEqual('block', next(iter(response.json())))
        self.assertEqual(200, response.status_code)

    def test_getblockbynumber_testnet(self):
        response = requests.get('http://127.0.0.1:5000/grpc/testnet/GetBlockByNumber/1')
        self.assertEqual('block', next(iter(response.json())))
        self.assertEqual(200, response.status_code)

if __name__ == '__main__':
    unittest.main()
