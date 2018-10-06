import logging
import hmac
import hashlib
import datetime
import time

# logging
logger = logging.getLogger(__name__)

# rfc6238
# https://www.ietf.org/rfc/rfc6238.txt
#
# HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))
# TOTP = HOTP(K, T)
# where T is an integer and represents the number of time steps
# between the initial counter time T0 and the current Unix time.
# T = (Current Unix time - T0) / X
# For example, with T0 = 0 and Time Step X = 30, T = 1 if the current
# Unix time is 59 seconds, and T = 2 if the current Unix time is
# 60 seconds.

class TOTP:
    def __init__(self, key=None, t_zero=0, time_step=30):
        self._digest = None

        if key is not None:
            self.update(key, t_zero, time_step)

    def update(self, key, time=None, t_zero=0, time_step=30, hash_name=None):
        if time is not None:
            return self.totp_core(key, time, t_zero, time_step, hash_name)
        return self.totp(key)

    def digest(self):
        return self._digest

    def current_time(self):
        now = datetime.datetime.now()
        unix_time = int(time.mktime(now.timetuple()))
        logger.info('now:%s, unix_time:%s', now, unix_time)
        return unix_time

    def totp_core(self, key, time, t_zero, time_step, hash_name):
        t = int((time - t_zero) / time_step)
        logger.info('key:%s, time:%s',key, time)
        t = self.int_to_byte(t)
        return self.dynamic_truncate(self.hmac_hash(key, t, hash_name))
        # return self.truncate(self.hmac_sha_1(key, t))

    # now, sha1
    def totp(self, key, t_zero=0, time_step=30):
        unix_time = self.current_time()
        return self.totp_core(key, unix_time, t_zero, time_step, 'SHA1')

    def hmac_hash(self, key, msg, hash_name=None):
        logger.debug('hash_name:%s', hash_name)
        if hash_name == 'SHA1':
            logger.debug('sha1 digest')
            _digest = hmac.new(key, msg, hashlib.sha1)
        elif hash_name == 'SHA256':
            logger.debug('sha256 digest')
            _digest = hmac.new(key, msg, hashlib.sha256)
        elif hash_name == 'SHA512':
            logger.debug('sha512 digest')
            _digest = hmac.new(key, msg, hashlib.sha512)
        else: # hash_name is None
            logger.debug('sha1 digest')
            _digest = hmac.new(key, msg, hashlib.sha1)

        hex_digest = _digest.hexdigest()
        bin_digest = _digest.digest()
        logger.debug('hex digest:%s, bin digest:%s', hex_digest, bin_digest)
        logger.debug('bin len%s', len(bin_digest))
        _len = len(bin_digest)
        logger.debug('byte%d:%s', _len-1, hex(bin_digest[_len-1]))
        return bin_digest

    def dynamic_truncate(self, bin_digest):
        logger.debug('bin_digest[%d]&0xf:%s', len(bin_digest), bin_digest[len(bin_digest)-1] & 0xf)
        offset = bin_digest[len(bin_digest)-1] & 0xf
        bin_code = (bin_digest[offset] & 0x7f) << 24 | (bin_digest[offset+1] & 0xff) << 16 | (bin_digest[offset+2] & 0xff) << 8 | (bin_digest[offset+3] & 0xff)
        logger.debug('bin_code:%s, hex(bin_code):%s', bin_code, hex(bin_code))
        # _hotp = '%08d' % (bin_code % 10**8)
        _totp = '{:08d}'.format(bin_code % 10**8)
        logger.info('TOTP:%s', _totp)
        self._digest = _totp
        return self._digest

    def str_to_byte(self, s):
        return bytes(s, 'ascii')

    def int_to_byte(self, i):
        return (i).to_bytes(8, byteorder='big')

def new(key=None, t_zero=0, time_step=30):
    return TOTP(key, t_zero, time_step)

def main():
    test = TOTP()

    _secret = "12345678901234567890"
    key = test.str_to_byte(_secret)
    print('totp 59:', test.totp_core(key, 59, 0, 30, 'SHA1'))
    print('totp now:', test.update(key))
    print('digit:', test.digest())


if __name__ == "__main__":
    main()


