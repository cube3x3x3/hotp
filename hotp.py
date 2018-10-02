import datetime
import time
import hmac
import hashlib

now = datetime.datetime.now()
print(now)

unix_time = int(time.mktime(now.timetuple()))
print(unix_time)

key = bytes("secret key", 'ascii')
text = bytes(str(unix_time), 'ascii')
dig = hmac.new(key, text, hashlib.sha1)
print(dig.hexdigest())

