import datetime
import time

now = datetime.datetime.now()
print(now)

unix = int(time.mktime(now.timetuple()))
print(unix)
