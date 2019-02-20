#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import racrypt
from os import path


class Amount(object):
    def __init__(self):
        self.integral = 0
        self.fraction = 0

class Transaction(object):
    def __init__(self):
        self.hash_hex = None
        self.sender_public = None
        self.receiver_public = None
        self.amount = Amount()
        self.currency = None
        self.salt = None



class TestCrypto(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(TestCrypto, self).__init__(*args, **kwargs)
        self.library = racrypt.Crypto()

    def setUp(self):
        pass

    def tearDown(self):
        pass

    #@unittest.skip("Load")
    def test_load(self):
        self.library.load(path.dirname(racrypt.__file__))
        self.assertIsNotNone(self.library.library)
        self.assertIsNotNone(self.library.lib_file)

    @unittest.skip("CreateKeys")
    def test_create_keys(self):
        self.library.load(path.dirname(racrypt.__file__))
        result = self.library.create_keys()
        self.assertTrue(result)
        self.assertIs(self.library.error, '')
        self.assertIsInstance(self.library.private_key, bytes)
        self.assertIsInstance(self.library.public_key, bytes)
        #self.assertIsInstance(self.library.private_key_hex, str)
        #self.assertIsInstance(self.library.public_key_hex, str)
        print(result)
        print(vars(self.library))

    @unittest.skip("Verify")
    def test_verify(self):
        self.library.load(path.dirname(racrypt.__file__))

        data = b'8Mt\x05\\h\xa5O\x8cpu ,\xbe\xb8\xf9\xff\xf8&^\x19:\xd7V\x96\x8b\xeb|<\xb6\xbd\xccn\xb2\x00' \
               b'\x00{\x00\x00\x00\x00\x00\x00\x00RAS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x008Mt' \
               b'\x05\\h\xa5O\x8cpu ,\xbe\xb8\xf9\xff\xf8&^\x19:\xd7V\x96\x8b\xeb|<\xb6\xbd\xcc'
        pub_key = b'8Mt\x05\\h\xa5O\x8cpu ,\xbe\xb8\xf9\xff\xf8&^\x19:\xd7V\x96\x8b\xeb|<\xb6\xbd\xcc'
        signature = b'\xc1\xc0-\x12\xcd\xad\xbcs\xdas\xcb\xd9\x98[*A\xff\xdb\x8d\xba\x9d\xe4p\xea' \
                    b'\xabE<\xc3Y^\xab1\xf8K\xbe\x07f\xae\xa9\x8bz\xb5H~\xb5\xf9b\xfc\x9c>\xd6\xb6' \
                    b'\x11\x96\x00B\x8dU\xba\xd3\x83\xbeP!'

        result = self.library.verify(data, pub_key, signature)
        print(result)
        # self.assertIs(result, 0)
        self.assertIsInstance(self.library.private_key, bytes)
        self.assertIsInstance(self.library.public_key, bytes)
        # self.assertIsInstance(self.library.private_key_hex, str)
        # self.assertIsInstance(self.library.public_key_hex, str)

    #@unittest.skip("Sign")
    def test_sign(self):
        self.library.load(path.dirname(racrypt.__file__))

        result = self.library.create_keys()
        print(result)

        import binascii
        import random

        test_key = (b'4b335fb3f5fe4669fa2bc7b384d68c377f4e4c1fec878e82bd09158ddb'
                    b'0c77f2')


        salt_sz = 32
        t = Transaction()

        t.sender_public = binascii.hexlify(self.library.public_key)
        t.receiver_public = binascii.hexlify(test_key)
        t.amount.integral = 1409
        t.amount.fraction = 0
        t.currency = b'RAS'
        t.salt = bytearray(salt_sz)
        for it in range(salt_sz):
            t.salt[it] = random.randint(0, 255)


        buffer = bytearray()
        buffer += binascii.unhexlify(t.sender_public)
        buffer += binascii.unhexlify(t.receiver_public)
        buffer += t.amount.integral.to_bytes(4, 'little')
        buffer += t.amount.fraction.to_bytes(8, 'little')
        buffer += t.currency
        buffer += bytearray(13)
        buffer += t.salt

        result = self.library.sign(
            bytes(buffer), len(buffer),
            self.library.public_key,
            self.library.private_key,
        )
        print(self.library.signature)
        self.assertTrue(result)


        result = self.library.verify(bytes(buffer),
                                     len(buffer),
                                     self.library.public_key,
                                     self.library.signature)
        self.assertTrue(result)




if __name__ == '__main__':
    unittest.main()
