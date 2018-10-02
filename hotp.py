import logging
import datetime
import time
import hmac
import hashlib
import unittest

# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def create_messsage_time(timestep):
    now = datetime.datetime.now()
    logger.debug('now:%s', now)

    unix_time = int(time.mktime(now.timetuple()))
    logger.info('unix_time:%s', unix_time)
    message_time = int(unix_time / timestep)
    return message_time

def create_hmacdigt(key, text):
    dig = hmac.new(key, text, hashlib.sha1)
    hexdig = dig.hexdigest()
    bindig = dig.digest()

    logger.debug('hexdig:%s, bindig:%s', hexdig, bindig)
    # print(bindig.hex())
    # print (hex(bindig))
    logger.debug('byte19:%s', hex(bindig[19]))
    return bindig

def HOTP_Computation(bindig):
    logger.debug('bindig[19]&0xf:%s', bindig[19] & 0xf)
    offset = bindig[19] & 0xf
    sn = (bindig[offset] & 0x7f) << 24 | (bindig[offset+1] & 0xff) << 16 | (bindig[offset+2] & 0xff) << 8 | (bindig[offset+3] & 0xff)
    logger.debug('sn:%s, hex(sn):%s', sn, hex(sn))
    ans = '%06d' % (sn % 10**6)
    logger.info('answer:%s', ans)
    return ans

timestep = 30
message_time = create_messsage_time(timestep)
key = bytes("secret key", 'ascii')
text = bytes(str(message_time), 'ascii')
bindig = create_hmacdigt(key, text)
n = 0
for i in bindig:
    logger.debug('%s, %s', n, hex(i))
    n = n + 1
logger.info('HOTP:%s', HOTP_Computation(bindig))

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


