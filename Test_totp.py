import hotp
import totp
import unittest
import logging

# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# logging.getLogger('').setLevel(logging.INFO)

class Test_totp(unittest.TestCase):
    def test_rfc6238_test_case(self):
        _secret = "12345678901234567890"
        key = totp.str_to_byte(_secret)
        t_zero = 0
        time_step = 30
        self.assertTrue(totp.totp(key, t_zero, time_step))

        # : '  Time (sec) ' , '   UTC Time   ' , ' Value of T (hex) ' , '   TOTP   ' , '  Mode  ' , 
        test_vectors = {
        0:  ("      59     " , "  1970-01-01  " , " 0000000000000001 " , " 46119246 " , " SHA256 " ), 
        1:  ("      59     " , "  1970-01-01  " , " 0000000000000001 " , " 90693936 " , " SHA512 " ), 
        2:  ("      59     " , "  1970-01-01  " , " 0000000000000001 " , " 94287082 " , "  SHA1  " ), 
        3:  ("  1111111109 " , "  2005-03-18  " , " 00000000023523EC " , " 07081804 " , "  SHA1  " ), 
        4:  ("  1111111109 " , "  2005-03-18  " , " 00000000023523EC " , " 25091201 " , " SHA512 " ), 
        5:  ("  1111111109 " , "  2005-03-18  " , " 00000000023523EC " , " 68084774 " , " SHA256 " ), 
        6:  ("  1111111111 " , "  2005-03-18  " , " 00000000023523ED " , " 14050471 " , "  SHA1  " ), 
        7:  ("  1111111111 " , "  2005-03-18  " , " 00000000023523ED " , " 67062674 " , " SHA256 " ), 
        8:  ("  1111111111 " , "  2005-03-18  " , " 00000000023523ED " , " 99943326 " , " SHA512 " ), 
        9:  ("  1234567890 " , "  2009-02-13  " , " 000000000273EF07 " , " 89005924 " , "  SHA1  " ), 
        10:  ("  1234567890 " , "  2009-02-13  " , " 000000000273EF07 " , " 91819424 " , " SHA256 " ), 
        11:  ("  1234567890 " , "  2009-02-13  " , " 000000000273EF07 " , " 93441116 " , " SHA512 " ), 
        12:  ("  2000000000 " , "  2033-05-18  " , " 0000000003F940AA " , " 38618901 " , " SHA512 " ), 
        13:  ("  2000000000 " , "  2033-05-18  " , " 0000000003F940AA " , " 69279037 " , "  SHA1  " ), 
        14:  ("  2000000000 " , "  2033-05-18  " , " 0000000003F940AA " , " 90698825 " , " SHA256 " ), 
        15:  (" 20000000000 " , "  2603-10-11  " , " 0000000027BC86AA " , " 47863826 " , " SHA512 " ), 
        16:  (" 20000000000 " , "  2603-10-11  " , " 0000000027BC86AA " , " 65353130 " , "  SHA1  " ), 
        17:  (" 20000000000 " , "  2603-10-11  " , " 0000000027BC86AA " , " 77737706 " , " SHA256 " ) 
        }
        logger.info('i:%s', test_vectors[1])
        logger.info('%s', test_vectors[1][4])
        for i in range(17):
            logger.info('%s', test_vectors[i])
            # Mode SHA1
            if test_vectors[i][4].strip() == "SHA1":
                _time = int(test_vectors[i][0])
                _totp = totp.totp_core(key, _time, 0, 30)
                _test_totp = test_vectors[i][3].strip()
                logger.info('i:%s, %s', i, _totp)
                self.assertEqual(_test_totp, _totp)


    def test_rfc4226_test_case(self):
        _secret = "12345678901234567890"
        _hotp = hotp.new()
        _key = _hotp.str_to_byte(_secret)
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
            _counter = _hotp.int_to_byte(i)
            logger.info('K:%s, C:%s', _key.hex(), _counter.hex())
            _bin_digest = _hotp.hmac_sha_1(_key, _counter)
            _hex_digest = _bin_digest.hex()
            logger.info("test_hexadecimal_array%d: %s", i, test_hexadecimal_array[i])
            self.assertEqual(test_hexadecimal_array[i], _hex_digest)
            logger.info("test_truncated_array%d:%s",i, test_truncated_array[i][2])            
            self.assertEqual(str(test_truncated_array[i][2]), _hotp.update(_key, _counter))

    def test_rfc_sample(self):
        import codecs
        # RFC 4226
        # https://www.ietf.org/rfc/rfc4226.txt
        # 5.4.  Example of HOTP Computation for Digit = 6
        example_value = codecs.decode(b'1f8698690e02ca16618550ef7f19da8e945b555a', 'hex_codec')
        _hotp = hotp.new()
        self.assertEqual('872921', _hotp.truncate(example_value))

    def test_hotp(self):
        key = bytes("12345678901234567890", 'ascii')
        counter = (0).to_bytes(8, byteorder='big')
        _hotp = hotp.new(key, counter)
        logger.info("test_hotp k=%s, c=%s, digest=%s", key, counter, _hotp.digest())
        self.assertTrue(_hotp.digest())
 
if __name__ == "__main__":
    unittest.main(exit=False)

