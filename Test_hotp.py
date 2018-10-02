import hotp
import unittest

class TestHOTP(unittest.TestCase):
    def test_rfc_sample(self):
        import codecs
        # RFC 4226
        # https://www.ietf.org/rfc/rfc4226.txt
        # 5.4.  Example of HOTP Computation for Digit = 6
        test = codecs.decode(b'1f8698690e02ca16618550ef7f19da8e945b555a', 'hex_codec')
        self.assertEqual('872921', HOTP_Computation(test))

    def test_create_HOTP(self):
        timestep = 30
        message_time= create_messsage_time(30)
        logger.info('messega_time %s', message_time)
        t_key = bytes("secret key", 'ascii')
        t_text = bytes(str(message_time), 'ascii')
        t_digest = create_hmacdigt(t_key, t_text)
        self.assertTrue(HOTP_Computation(t_digest))

    def test_fixedtime_HOTP(self):
        fixed_message_time = int(51282858)
        logger.info('fixed_message_time:%s', fixed_message_time)
        f_key = bytes("secret key", 'ascii')
        f_text = bytes(str(fixed_message_time), 'ascii')
        f_bindig = create_hmacdigt(f_key, f_text)
        self.assertEqual('811807', HOTP_Computation(f_bindig))


if __name__ == "__main__":
    unittest.main(exit=False)

