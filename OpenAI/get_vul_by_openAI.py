import openai
import ast
import requests
import json
import base64
import string
import re
from bs4 import BeautifulSoup


api_key_no1 = "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"
openai.api_key = api_key_no1

# get all vulnerabilities from file
f = open("./OpenAI/template_vuln.txt", "r")
template_vuln = ast.literal_eval(f.read())
f.close()

template_vuln_allname = ""
for item in template_vuln:
    template_vuln_allname += item['template_name'] + "\n"

def write_file_respon(respon):
  
    sample_string_bytes = base64.b64decode(respon) 
    sample_string = sample_string_bytes.decode("utf-8")

    file1 = open('./OpenAI/response.txt', 'w')
    file1.writelines(sample_string)
    
    file1.close()

def custom_response():
    file_path = './OpenAI/response.txt'
    with open(file_path, 'r') as file:
        response = file.read()

    header_lines, html_content = response.split("\n\n", 1)
    headers = dict(line.split(": ", 1) for line in header_lines.split("\n")[1:])

    new_html_content = ''

    for key, value in headers.items():
        header = f"{key}: {value}"
        new_html_content = new_html_content + header + '\n'

    soup = BeautifulSoup(html_content, 'html.parser')

    head_content = soup.head

    new_html_content = new_html_content + '\n'

    new_html_content1 = f"<!DOCTYPE html>\n<html>\n{head_content}\n<body>\n"
    new_html_content2 = f"\n</body>\n</html>"

    new_html_content = new_html_content + new_html_content1
    input_tags = soup.find_all("input")

    for input_tag in input_tags:
        new_html_content = new_html_content + str(input_tag) + '\n'

    new_html_content = new_html_content + new_html_content2

    return new_html_content

def connect_chatGPT(question):
    messages = [
        {"role": "user", "content": question},
    ]
    
    completion = openai.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=messages
    )
    output_from_chatGPT = completion.choices[0].message.content
    return output_from_chatGPT

def question(request, response):
    template_vuln_allname = ""
    for item in template_vuln:
        template_vuln_allname += item['template_name'] + "\n"

    question_list_vuln = "This is my list of vulnerabilities and you can only use vulnerabilities from this list to recommend what vulnerabilities can happened with the given HTTP request and response (I will give you later):\n"+str(
        template_vuln_allname)+"Please remember this list while recommending potential vulnerabilities for me and do not use anything outside this list and just suggesting possible errors for this request?"
    question_request = "Recommend vulnerabilities can happened with this HTTP request and response: " + "\n +Requests: " + request + "\n +Response: " + response + "\nYour answer only needs to include the name of the vulnerability and no need to explain it?"

    return question_list_vuln + question_request

def encode_base64(strings):
  
    sample_string_bytes = base64.b64decode(strings) 
    sample_string = sample_string_bytes.decode("utf-8")
    return sample_string

def get_vul(request, response):
    write_file_respon(response)

    response = custom_response()

    # Question for openAI
    output_from_openAI = connect_chatGPT(question(encode_base64(request), response))
        
    recommend_testcase = []
    for vul in template_vuln:
        if vul['template_name'] in output_from_openAI:
            vuln = f"{vul['template_name']} " + "</br>"
            recommend_testcase.append(vuln)
    text_vul = ' '.join([str(vul) for vul in recommend_testcase])
    return text_vul