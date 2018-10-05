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
 
if __name__ == "__main__":
    unittest.main(exit=False)

