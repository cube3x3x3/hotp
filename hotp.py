import datetime
import time
import hmac
import hashlib

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

print(hexdig, bindig)
print(bindig.hex())

print(bindig[3])

n = 0
for i in bindig:
    print(n, i)
    n = n + 1

print(bindig[19] & 0xf)
offset = bindig[19] & 0xf
sn = (bindig[offset] & 0x7f) << 24 | (bindig[offset+1] & 0xff) << 16 | (bindig[offset+2] & 0xff) << 8 | (bindig[offset+3] & 0xff)

print (sn)

ans = '%06d' % (sn % 10**6)
print(ans)




