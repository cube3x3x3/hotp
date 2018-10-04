import logging
import hmac
import hashlib

# logging
logger = logging.getLogger(__name__)

# rfc4226
# https://www.ietf.org/rfc/rfc4226.txt
#
# HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))

def hotp(key, counter):
    return truncate(hmac_sha_1(key, counter))

def hmac_sha_1(key, counter):
    _digest = hmac.new(key, counter, hashlib.sha1)
    hex_digest = _digest.hexdigest()
    bin_digest = _digest.digest()

    logger.debug('hex digest:%s, bin digest:%s', hex_digest, bin_digest)
    logger.debug('byte19:%s', hex(bin_digest[19]))
    return bin_digest

def truncate(bin_digest):
    logger.debug('bin_digest[19]&0xf:%s', bin_digest[19] & 0xf)
    offset = bin_digest[19] & 0xf
    bin_code = (bin_digest[offset] & 0x7f) << 24 | (bin_digest[offset+1] & 0xff) << 16 | (bin_digest[offset+2] & 0xff) << 8 | (bin_digest[offset+3] & 0xff)
    logger.debug('bin_code:%s, hex(bin_code):%s', bin_code, hex(bin_code))
    _hotp = '%06d' % (bin_code % 10**6)
    logger.info('HOTP:%s', _hotp)
    return _hotp

def str_to_byte(s):
    return bytes(s, 'ascii')

def int_to_byte(i):
    return (i).to_bytes(8, byteorder='big')

def main():
    key = bytes("secret key", 'ascii')
    counter = bytes(0)
    print('hotp', hotp(key, counter))


if __name__ == "__main__":
    main()
