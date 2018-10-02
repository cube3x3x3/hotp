import datetime
import time
import hmac
import hashlib
import codecs

timestep = 30

now = datetime.datetime.now()
print(now)

unix_time = int(time.mktime(now.timetuple()))
print(unix_time)
message_time = int(unix_time / timestep)
print(message_time)

key = bytes("secret key", 'ascii')
text = bytes(str(message_time), 'ascii')
dig = hmac.new(key, text, hashlib.sha1)
hexdig = dig.hexdigest()
bindig = dig.digest()

# RFC 4226
# https://www.ietf.org/rfc/rfc4226.txt
# 5.4.  Example of HOTP Computation for Digit = 6
test = codecs.decode(b'1f8698690e02ca16618550ef7f19da8e945b555a', 'hex_codec')

bindig = test
print(hexdig, bindig)
# print(bindig.hex())
# print (hex(bindig))
print('byte19', hex(bindig[19]))

n = 0
for i in bindig:
    print(n, hex(i))
    n = n + 1

print(bindig[19] & 0xf)
offset = bindig[19] & 0xf
sn = (bindig[offset] & 0x7f) << 24 | (bindig[offset+1] & 0xff) << 16 | (bindig[offset+2] & 0xff) << 8 | (bindig[offset+3] & 0xff)

print (sn, hex(sn))

ans = '%06d' % (sn % 10**6)
print(ans)




