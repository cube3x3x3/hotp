import hotp
import unittest
import logging

# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# logging.getLogger('').setLevel(logging.INFO)

class Test_hotp(unittest.TestCase):

    def test_rfc4226_test_case(self):
        _secret = "12345678901234567890"
        _key = hotp.str_to_byte(_secret)
        self.assertEqual('3132333435363738393031323334353637383930', _key.hex())
        # Secret = 0x3132333435363738393031323334353637383930

        #   Count    Hexadecimal HMAC-SHA-1(secret, count)
        test_hexadecimal_array={
        0:        "cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
        1:        "75a48a19d4cbe100644e8ac1397eea747a2d33ab",
        2:        "0bacb7fa082fef30782211938bc1c5e70416ff44",
        3:        "66c28227d03a2d5529262ff016a1e6ef76557ece",
        4:        "a904c900a64b35909874b33e61c5938a8e15ed1c",
        5:        "a37e783d7b7233c083d4f62926c7a25f238d0316",
        6:        "bc9cd28561042c83f219324d3c607256c03272ae",
        7:        "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
        8:        "1b3c89f65e6c9e883012052823443f048b4332db",
        9:        "1637409809a679dc698207310c8c7fc07290d9e5"}

        #                     Truncated
        #Count    Hexadecimal    Decimal        HOTP
        test_truncated_array={
        0:        ("4c93cf18",       1284755224,     755224),
        1:        ("41397eea",       1094287082,     287082),
        2:         ("82fef30",        137359152,     359152),
        3:        ("66ef7655",       1726969429,     969429),
        4:        ("61c5938a",       1640338314,     338314),
        5:        ("33c083d4",        868254676,     254676),
        6:        ("7256c032",       1918287922,     287922),
        7:         ("4e5b397",         82162583,     162583),
        8:        ("2823443f",        673399871,     399871),
        9:        ("2679dc69",        645520489,     520489)}

        for i in range(10):
            _counter = hotp.int_to_byte(i)
            logger.info('K:%s, C:%s', _key.hex(), _counter.hex())
            _bin_digest = hotp.hmac_sha_1(_key, _counter)
            _hex_digest = _bin_digest.hex()
            logger.info("test_hexadecimal_array%d: %s", i, test_hexadecimal_array[i])
            self.assertEqual(test_hexadecimal_array[i], _hex_digest)
            logger.info("test_truncated_array%d:%s",i, test_truncated_array[i][2])
            self.assertEqual(str(test_truncated_array[i][2]), hotp.hotp(_key, _counter))

    def test_rfc_sample(self):
        import codecs
        # RFC 4226
        # https://www.ietf.org/rfc/rfc4226.txt
        # 5.4.  Example of HOTP Computation for Digit = 6
        example_value = codecs.decode(b'1f8698690e02ca16618550ef7f19da8e945b555a', 'hex_codec')
        self.assertEqual('872921', hotp.truncate(example_value))

if __name__ == "__main__":
    unittest.main(exit=False)

