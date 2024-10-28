import requests
from zapv2 import ZAPv2 as ZAP
import time
from os import getcwd

target_url = "http://localhost:9090"
sess = requests.Session()
proxies = {
    'http': 'http://127.0.0.1:8090',
    'https': 'http://127.0.0.1:8090',
}

data = {"name": "cicd", "username": "cicd", "email": "cicd@test.org", "password": "cicd", "cpassword": "cicd"}
response = requests.post(target_url+'/register', data=data, proxies=proxies, verify=False) #register test account
data = {"username": "cicd", "password": "cicd"}
login = sess.post(target_url+'/login', data= data, allow_redirects=False, proxies=proxies, verify=False) # login test account

if 'learn' in login.text:  # if login is successful
    print('Successful Login')
    # run operations
    data = {"login": "cicd"}
    response = sess.post(target_url+'/app/usersearch',data= data, proxies=proxies, verify=False) # user search functionality
    print("user search completed" if "200" == str(response.status_code) else "[!] failed")

    data = {"address": "127.0.0.1"}
    response = sess.post(target_url+'/app/ping',data= data, proxies=proxies, verify=False) # connectivity check functionality
    print("connectivity check completed" if "200" == str(response.status_code) else "[!] failed")

    data = {"name": "test"}
    response = sess.post(target_url+'/app/products',data= data, proxies=proxies, verify=False) # product search functionality
    print("product search completed" if "200" == str(response.status_code) else "[!] failed")
else:
    print('Login Failed !!')
    print(login.text)

# ZAP Operations
zap = ZAP(proxies={'http': 'http://localhost:8090',
                   'https': 'http://localhost:8090'})

if 'Light' not in zap.ascan.scan_policy_names:
    print("Adding scan policies")
    zap.ascan.add_scan_policy(
        "Light", alertthreshold="Low", attackstrength="Low")

active_scan_id = zap.ascan.scan(target_url, scanpolicyname='Light')

print("active scan id: {0}".format(active_scan_id))

# now we can start monitoring the spider's status
while int(zap.ascan.status(active_scan_id)) < 100:
    print("Current Status of ZAP Active Scan: {0}%".format(
        zap.ascan.status(active_scan_id)))
    time.sleep(10)

# Report generate
path = getcwd()
r = requests.get('http://localhost:8090/JSON/reports/action/generate/', params={'title': 'DAST-Report',  'template': 'sarif-json', 'reportDir':path, 'reportFileName': 'dast_report_sarif'}, headers = {'Accept': 'application/json'})
print(r.json())
r = requests.get('http://localhost:8090/JSON/reports/action/generate/', params={'title': 'DAST-Report',  'template': 'traditional-html-plus', 'reportDir':path, 'reportFileName': 'dast_report_html'}, headers = {'Accept': 'application/json'})
print(r.json())

zap.core.shutdown()
