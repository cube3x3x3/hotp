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

def totp_core(key, time, t_zero, time_step):
    t = int((time - t_zero) / time_step)
    logger.info('key:%s, time:%s',key, time)
    t = int_to_byte(t)
    return truncate(hmac_sha_1(key, t))

def totp(key, t_zero=0, time_step=30):
    now = datetime.datetime.now()
    unix_time = int(time.mktime(now.timetuple()))
    t = int((unix_time - t_zero) / time_step)
    logger.info('now:%s, unix_time:%s, k:%s, t:%s', now, unix_time, key, t)
    t = int_to_byte(t)
    return truncate(hmac_sha_1(key, t))

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
    _hotp = '%08d' % (bin_code % 10**8)
    logger.info('TOTP:%s', _hotp)
    return _hotp

def str_to_byte(s):
    return bytes(s, 'ascii')

def int_to_byte(i):
    return (i).to_bytes(8, byteorder='big')

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

def main():
    timestep = 30
    message_time = create_messsage_time(timestep)
    key = bytes("secret key", 'ascii')
    text = bytes(str(message_time), 'ascii')
    bindig = create_hmacdigt(key, text)
    print('HOTP:', HOTP_Computation(bindig))

    _secret = "12345678901234567890"
    key = str_to_byte(_secret)
    counter = int_to_byte(0)
    print('hotp', hotp(key, counter))
    print('totp', totp_core(key, 59, 0, 30))



if __name__ == "__main__":
    main()


