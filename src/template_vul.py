import sqlite3

def get_db_connection():
    conn = sqlite3.connect(r'./database.db')
    conn.row_factory = sqlite3.Row
    return conn

def X_xss(id, url, user,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'X-XSS-Protection Header is missing'
    bugurl = url
    cweid = 'CWE-693'
    risk = 'Informational'
    description = '''Invicti detected a missing X-XSS-Protection header which means that this website could be at risk of a Cross-site Scripting (XSS) attacks.'''
    impact= "Can lead to XSS "
    solution = '''Add the X-XSS-Protection header with a value of "1; mode= block".
    X-XSS-Protection: 1; mode=block
Please also be advised that in some specific cases enabling XSS filter can be abused by attackers. However, in most cases, it provides basic protection for users against XSS attacks.
            '''
    pentester = user
    reference = '''https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/missing-x-xss-protection-header/'''
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                            impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        
        
def HSTS(id, url, user,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Strict-Transport-Security Header is Missing'
    bugurl = url
    cweid = 'CWE-523'
    risk = 'Low'
    description = "The header to enable the mechanism to force the browser to use HTTPS communication (HTTP Strict Transport Security) is not set."
    impact = "Vulnerabilities such as unset Secure attribute or unused HTTPS are vulnerable to attack when they are exploited."
    solution = '''
            Depending on the framework being used the implementation methods will vary, however it is advised that the `Strict-Transport-Security` header be configured on the server.
One of the options for this header is `max-age`, which is a representation (in milliseconds) determining the time in which the client's browser will adhere to the header policy.
Depending on the environment and the application this time period could be from as low as minutes to as long as days.
            
            '''
    pentester = user
    reference = '''
https://kinsta.com/knowledgebase/hsts-missing-from-https-server/#:~:text=Sometimes%2C%20an%20IT%20security%20scan,as%20a%20medium%2Drisk%20vulnerability.
https://www.ibm.com/support/pages/resolving-missing-hsts-or-missing-http-strict-transport-security-websphere
            '''
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()  

def CSP(id, url, user,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Content Security Policy (CSP) not implemented'
    bugurl = url
    cweid = 'CWE-523'
    risk = 'Low'
    description = '''
Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks.

Content Security Policy (CSP) can be implemented by adding a Content-Security-Policy header. The value of this header is a string containing the policy directives describing your Content Security Policy. To implement CSP, you should define lists of allowed origins for the all of the types of resources that your site utilizes        
            '''
    impact = "There is no direct impact of not implementing CSP on your website."
    solution = '''
It's recommended to implement Content Security Policy (CSP) into your web application. Configuring Content Security Policy involves adding the Content-Security-Policy HTTP header to a web page and giving it values to control resources the user agent is allowed to load for that page.
            '''
    pentester = user
    reference = '''
https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
https://hacks.mozilla.org/2016/02/implementing-content-security-policy/
            '''
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        
        
def XFrame(id, url, user,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'X-Frame-Options Header is Missing'
    bugurl = url
    cweid = 'CWE-613'
    risk = 'Low'
    description = '''
The X-Frame-Options HTTP header field indicates a policy that specifies whether the browser should render the transmitted resource within a frame or an iframe. Servers can declare this policy in the header of their HTTP responses to prevent clickjacking attacks, which ensures that their content is not embedded into other pages or frames.
            '''
    solution = '''
Sending the proper X-Frame-Options in HTTP response headers that instruct the browser to not allow framing from other domains.
    X-Frame-Options: DENY  It completely denies to be loaded in frame/iframe.
    X-Frame-Options: SAMEORIGIN It allows only if the site which wants to load has a same origin.
    X-Frame-Options: ALLOW-FROM URL It grants a specific URL to load itself in a iframe. However please pay attention to that, not all browsers support this.
Employing defensive code in the UI to ensure that the current frame is the most top level window.
            '''
    pentester = user
    reference = '''
            https://www.iothreat.com/blog/x-content-type-options-header-missing#:~:text=The%20'X%2DContent%2DType,perform%20content%2Dtype%20sniffing%20attacks.
            '''
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod) VALUES (?,?,?,?,?,?,?,?,?,?)',
                                            (id,
                                            name.encode('latin-1', 'replace').decode('latin-1'),
                                            bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                            cweid.encode('latin-1', 'replace').decode('latin-1'),
                                            description.encode('latin-1', 'replace').decode('latin-1'),
                                            solution.encode('latin-1', 'replace').decode('latin-1'),
                                            risk.encode('latin-1', 'replace').decode('latin-1'),
                                            reference.encode('latin-1', 'replace').decode('latin-1'),
                                            pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()

def X_Content(id, url, user,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'X-Content-Type-Options Header is Missing'
    bugurl = url
    cweid = 'CWE-643'
    risk = 'Low'
    description = '''
The Anti-MIME-Sniffing header X-Content-Type-Options was not set to ’nosniff’. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.
            '''
    solution = '''
Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages. If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.
            '''
    pentester = user
    reference = '''
https://www.iothreat.com/blog/x-content-type-options-header-missing#:~:text=The%20'X%2DContent%2DType,perform%20content%2Dtype%20sniffing%20attacks.
https://www.zaproxy.org/docs/alerts/10021/
http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx
            '''
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod) VALUES (?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit() 
    
  
def Server_infor(id, url, user,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = "Server Leaks Information via 'X-Powered-By' HTTP Response Header Field(s)"
    bugurl = url
    cweid = 'CWE-200'
    risk = 'Medium'
    description = '''
The web/application server is leaking information via one or more “X-Powered-By” HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.
            '''
    solution = '''
Ensure that your web server, application server, load balancer, etc. is configured to suppress 'X-Powered-By' headers.
            '''
    pentester = user
    reference = '''
http://blogs.msdn.com/b/varunm/archive/2013/04/23/remove-unwanted-http-response-headers.aspx
http://www.troyhunt.com/2012/02/shhh-dont-let-your-response-headers.html
            '''
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod) VALUES (?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit() 


def Cookie_secure(id, url, user,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'TLS cookie without secure flag set'
    bugurl = url
    cweid = 'CWE-614'
    risk = 'Medium'
    description = '''
If the secure flag is set on a cookie, then browsers will not submit the cookie in any requests that use an unencrypted HTTP connection, thereby preventing the cookie from being trivially intercepted by an attacker monitoring network traffic. If the secure flag is not set, then the cookie will be transmitted in clear-text if the user visits any HTTP URLs within the cookie's scope. An attacker may be able to induce this event by feeding a user suitable links, either directly or via another web site. Even if the domain that issued the cookie does not host any content that is accessed over HTTP, an attacker may be able to use links of the form http://example.com:443/ to perform the same attack.
                '''
    solution = '''
The secure flag should be set on all cookies that are used for transmitting sensitive data when accessing content over HTTPS. If cookies are used to transmit session tokens, then areas of the application that are accessed over HTTPS should employ their own session handling mechanism, and the session tokens used should never be transmitted over unencrypted communications.
                '''
    pentester = user
    reference = '''
https://owasp.org/www-community/controls/SecureCookieAttribute
                '''
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod) VALUES (?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit() 


def Cookie_httponly(id, url, user,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Cookie Without HttpOnly Flag Set'
    bugurl = url
    cweid = 'CWE-16'
    risk = 'Medium'
    description = "If the HttpOnly attribute is set on a cookie, then the cookie's value cannot be read or set by client-side JavaScript. This measure makes certain client-side attacks, such as cross-site scripting, slightly harder to exploit by preventing them from trivially capturing the cookie's value via an injected script."
    solution = '''
There is usually no good reason not to set the HttpOnly flag on all cookies. Unless you specifically require legitimate client-side scripts within your application to read or set a cookie's value, you should set the HttpOnly flag by including this attribute within the relevant Set-cookie directive.
You should be aware that the restrictions imposed by the HttpOnly flag can potentially be circumvented in some circumstances, and that numerous other serious attacks can be delivered by client-side script injection, aside from simple cookie stealing.
                '''
    pentester = user
    reference = '''
https://portswigger.net/research/web-storage-the-lesser-evil-for-session-tokens#httponly
                '''
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod) VALUES (?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit() 

           
# ------------------------------------ #

def template_SQLi(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'SQL Injection'
    bugurl = url
    cweid = 'CWE-89'
    risk = 'High'
    description = "SQL injection, also known as SQLI, is a common attack vector that uses malicious SQL code for backend database manipulation to access information that was not intended to be displayed. This information may include any number of items, including sensitive company data, user lists or private customer details"
    impact = "Information in the database may be leaked.In addition, there is a risk of alteration."
    solution = "The only sure way to prevent SQL Injection attacks is input validation and parametrized queries including prepared statements. The application code should never use the input directly. The developer must sanitize all input, not only web form inputs such as login forms. They must remove potential malicious code elements such as single quotes. It is also a good idea to turn off the visibility of database errors on your production sites. Database errors can be used with SQL Injection to gain information about your database"
    pentester = user
    reference = '''
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit() 
        

def template_SSTI(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Server Side Template Injection(SSTI)'
    bugurl = url
    cweid = 'CWE-1336'
    risk = 'High'
    description = "Malicious code can be executed because the parameter value is interpreted as template string."
    impact = "The contents of files on the server may be leaked or modified;The attacker may use the server as a stepping stone to attack other servers;If a large amount of computation is forced, the server may become overloaded."
    solution = "Do not use user input where they are interpreted as template.Associate the parameter value with a unique identifier on the server side in advance. Acquire and use the value according to the identifier sent from the client."
    pentester = user
    reference = '''
https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
  
      
def template_Open_Redirect(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Open Redirect'
    bugurl = url
    cweid = 'CWE-601'
    risk = 'Low'
    description = "This function may be used as a redirector to an external site because the parameter value is output to the redirection destination URL in the response."
    impact = "The attacker may force users to transition to a malicious site for phishing and other scams using the vulnerability."
    solution = "Prevent client from freely specifying URL.Associate a redirect destination URL with a unique identifier in advance on the server side. Acquire and use the URL according to the identifier sent from the client; If it is necessary to use URL from client, validate the absolute URL by the forward match search including the slash "/" after hostname, as shown below; Prevent tampering of the parameter for redirect destination. For example, use Message Authentication Code (MAC)."
    pentester = user
    reference = '''
https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        

def template_OS_Command(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'OS Command Injection'
    bugurl = url
    cweid = 'CWE-78'
    risk = 'High'
    description = "Parameter input value is used in processes such as executing shell command without proper validation. Thus the input value is interpreted as OS commands."
    impact = "The contents of files on the server may be leaked or modified;The attacker may use the server as a stepping stone to attack other servers;Information about the system may be leaked."
    solution = "Do not use functions that invokes shell.Also, define allowed character types for the parameter and validate the value on the server side. Return an error if an unintended value is given."
    pentester = user
    reference = '''
https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
 
        
def template_path_travel(id, url, user,result_scan, method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Path Traversal'
    bugurl = url
    cweid = 'CWE-98'
    risk = 'High'
    reference = '''
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
            '''
    description = "It is possible to obtain a file content that is not normally accessible because the parameter input is used in the file access process without proper validation."
    solution = "The most effective solution to eliminate file inclusion vulnerabilities is to avoid passing user-submitted input to any filesystem/framework API. If this is not possible the application can maintain an allow list of files, that may be included by the page, and then use an identifier (for example the index number) to access to the selected file. Any request containing an invalid identifier has to be rejected, in this way there is no attack surface for malicious users to manipulate the path."
    impact = "This can lead to something as outputting the contents of the file, but depending on the severity, it can also lead to:Code execution on the web server,Code execution on the client-side such as JavaScript which can lead to other attacks such as cross site scripting (XSS),Denial of Service (DoS),Sensitive Information Disclosure."
    pentester = user
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        

def template_XSS(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Cross-Site Scripting'
    bugurl = url
    cweid = 'CWE-79'
    risk = 'High'
    description = "Since parameter input is output to the response with no escaping, a malicious script is executed."
    impact = "The attacker obtains the Cookie used as session ID;The attacker rides on the victim's session and access functions that do not require re-authentication;The attacker alters the appearance of a page and use it for malicious purposes such as phishing."
    solution = "Escape special symbols to character references when outputting.Also, if limited character types are expected for the parameter, validate the value on the server side. Return an error if an unintended value is given."
    pentester = user
    reference = '''
        https://owasp.org/www-community/attacks/xss/
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        
        
def template_CORS(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Cross-Origin Resource Sharing'
    bugurl = url
    cweid = 'CWE-523'
    risk = 'Medium'
    description = "Inappropriate policies are defined in headers to control cross-domain access."
    impact = "When accessing a maliciously installed trap page, the information handled on the corresponding website can be stolen."
    solution = '''
It’s primarily web server misconfigurations that enable CORS vulnerabilities. The solution is to prevent the vulnerabilities from arising in the first place by properly configuring your web server’s CORS policies
    1. Specify the allowed origins
    2. Only allow trusted sites
    3. Don’t whitelist “null”
    4. Implement proper server-side security policies
            '''
    pentester = user
    reference = '''
https://www.freecodecamp.org/news/exploiting-cors-guide-to-pentesting/
https://ranakhalil.teachable.com/p/web-security-academy-video-series
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        

def template_find_script(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Java Script Exposure'
    bugurl = url
    cweid = 'CWE-749'
    risk = 'Informational'
    description = "In a page protected by HTTPS, part of the contents that composes the page is loaded by HTTP."
    impact = "HTTPS pages can be compromised by tampering HTTP contents."
    solution = "Load all contents of HTTPS page via HTTPS."
    pentester = user
    reference = '''
https://cwe.mitre.org/data/definitions/749.html
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        

def template_find_comment(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Comment Exposure'
    bugurl = url
    cweid = 'CWE-615'
    risk = 'Informational'
    description = "Information that does not need to be disclosed to the user is output in the response as HTML and JavaScript comments."
    impact = "The attacker may obtain information useful to further attack."
    solution = "Delete unnecessary information contained in the contents."
    pentester = user
    reference = '''
https://cwe.mitre.org/data/definitions/615.html
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        
def template_sameSite_attribute(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Improper SameSite Attribute'
    bugurl = url
    cweid = 'CWE-1275'
    risk = 'Informational'
    description = "The SameSite attribute for the Cookie that is used as a Session ID is an insecure value is used."
    impact = "Susceptibility to cross-site attacks such as cross-site request forgery and cross-site scripting."
    solution = 'When issuing a cookie to be treated as a session ID, add a SameSite attribute set to either "Lax" or "Strict".However, in the case of a system consisting of multiple domains, it is possible that this countermeasure may cause the system to fail to operate properly.'
    pentester = user
    reference = '''
https://cwe.mitre.org/data/definitions/1275.html
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        
def template_http_method(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Unnecessary HTTP Methods Enabled'
    bugurl = url
    cweid = 'CWE-650'
    risk = 'Informational'
    description = "There is a flaw in the web server configuration and the Allow header contains methods that seem unnecessary, which can be exploited."
    impact = "Files on the server may be created / deleted etc. by the attacker."
    solution = "Change the settings of the web server and disable unnecessary methods."
    pentester = user
    reference = '''
https://cwe.mitre.org/data/definitions/650.html
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
     
     
###          
def template_component(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Third-Party Component Vulnerability'
    bugurl = url
    cweid = 'CWE-'
    risk = 'Informational'
    description = "The application relies on a third-party component with a known vulnerability."
    impact = "An attacker could exploit this vulnerability to compromise the security of the application."
    solution = "Upgrade the third-party component to the latest, patched version or apply recommended security measures."
    pentester = user
    reference = '''CVE Details: https://www.cvedetails.com/'''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
  
        
def template_check_http_https(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Lack of HTTPS Encryption'
    bugurl = url
    cweid = 'CWE-311'
    risk = 'Medium'
    description = "HTTPS is not used for the entire site /function. Critical data is transmitted on the communication path without being encrypted."
    impact = "If the communications is intercepted, important information may be stolen."
    solution = "The functions that send and receive critical data should be provided via HTTPS;It is recommended that the following header be set in the response to force the browser to use HTTPS connection (HTTP Strict Transport Security)."
    pentester = user
    reference = '''
https://cwe.mitre.org/data/definitions/311.html
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        

######
def template_hidden_path(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Hidden Path Discovery'
    bugurl = url
    cweid = 'CWE-'
    risk = 'Medium'
    description = "The application allows for hidden path discovery, which could expose sensitive information or functionality."
    impact = "An attacker may discover hidden paths, leading to potential information disclosure or unauthorized access."
    solution = "Ensure that all sensitive paths are properly secured and not discoverable through the application interface."
    pentester = user
    reference = '''OWASP: https://www.owasp.org/'''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        
        
def template_JWT(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'JWT Weak Secret Key'
    bugurl = url
    cweid = 'CWE-1270'
    risk = 'Low'
    description = "JWTs are generated using secret keys that are easy to guess, making them vulnerable to attackers."
    impact = "Information stored in JWT may be tampered with and misused for further attacks."
    solution = "A random string of sufficient length that cannot be easily guessed is used as the secret key for signing.A public key cryptographic algorithm is used for signing."
    pentester = user
    reference = '''
https://cwe.mitre.org/data/definitions/650.html
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        
def template_CRLF(id, url, user, result_scan,method):
    request_have_bug = 1
    conn = get_db_connection()
    name = 'Improper Neutralization of CRLF Sequences (CRLF Injection)'
    bugurl = url
    cweid = 'CWE-93'
    risk = 'Low'
    description = "A CRLF Injection attack occurs when a user manages to submit a CRLF into an application. This is most commonly done by modifying an HTTP parameter or URL."
    impact = "Depending on how the application is developed, this can be a minor problem or a fairly serious security flaw."
    solution = "Ensure that all user inputs are properly validated before they are used. Reject or sanitize any input that contains CRLF characters"
    pentester = user
    reference = '''
https://cwe.mitre.org/data/definitions/93.html
            '''
    detail = result_scan
    duplicate = conn.execute('SELECT * FROM bugs WHERE requestid = ? AND bugurl = ? AND name = ?',(id,bugurl,name)).fetchone()
    if duplicate is None:
        conn.execute('INSERT INTO bugs (requestid,name,bugurl,cweid,description,solution,risk,reference,pentester,bugsmethod,detail,impact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                                    (id,
                                    name.encode('latin-1', 'replace').decode('latin-1'),
                                    bugurl.encode('latin-1', 'replace').decode('latin-1'),
                                    cweid.encode('latin-1', 'replace').decode('latin-1'),
                                    description.encode('latin-1', 'replace').decode('latin-1'),
                                    solution.encode('latin-1', 'replace').decode('latin-1'),
                                    risk.encode('latin-1', 'replace').decode('latin-1'),
                                    reference.encode('latin-1', 'replace').decode('latin-1'),
                                    pentester.encode('latin-1', 'replace').decode('latin-1'),method.encode('latin-1', 'replace').decode('latin-1'),
                                    detail.encode('latin-1', 'replace').decode('latin-1'),
                                    impact.encode('latin-1', 'replace').decode('latin-1')))
        conn.commit()
        
