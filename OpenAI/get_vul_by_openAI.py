import openai
import ast
import requests
import json
import base64
import string
import re

api_key_no1 = "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"
openai.api_key = api_key_no1

# get all vulnerabilities from file
f = open("./OpenAI/template_vuln.txt", "r")
template_vuln = ast.literal_eval(f.read())
f.close()

# f = open("infor_req_paren.txt", "r")
# get_requests_response = ast.literal_eval(f.read()) #list
# f.close()

# list_req = list(get_requests_response)
# print(get_requests_response[list_req[0]][0]['request'])

template_vuln_allname = ""
for item in template_vuln:
    template_vuln_allname += item['template_name'] + "\n"

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
    # base64_bytes = strings.encode("utf-8") 
  
    sample_string_bytes = base64.b64decode(strings) 
    sample_string = sample_string_bytes.decode("utf-8")
    return sample_string

def get_vul(request, response):
    # Question for openAI
    output_from_openAI = connect_chatGPT(question(encode_base64(request), encode_base64(response)))
    # print(output_from_openAI)
        
    recommend_testcase = []
    for vul in template_vuln:
        if vul['template_name'] in output_from_openAI:
            # vuln = {'id': vul['id'], 'template_name': vul['template_name']}
            vuln = f"{vul['template_name']} " + "</br>"
            recommend_testcase.append(vuln)
    text_vul = ' '.join([str(vul) for vul in recommend_testcase])
    return text_vul