from flask import Flask,Response, request, url_for, redirect, render_template,session
import sqlite3
from flask_session import Session
from datetime import datetime
from fpdf import FPDF
import sqlite3
from datetime import datetime
from src.unauthen import UnauthenScanHeaders,unau_path_travel_scan
from src.scan import scan_hidden_path, scan_component, scan_crlf, scan_OS_cmd, has_same_site_attribute, scan_SQLi, find_comments,find_javascript_code, scan_SSTI, check_http_method, check_http_https, scan_CORS, scan_XSS, scan_JWT_Token, has_httponly_attribute, has_secure_attribute, is_jwt_used, write_file
from src.template_vul import XFrame, X_Content, HSTS, CSP, Server_infor, Cookie_secure, Cookie_httponly, template_SQLi, template_SSTI, template_OS_Command, template_path_travel, template_XSS, template_CORS, template_find_script, template_find_comment, template_sameSite_attribute, template_http_method, template_component, template_check_http_https, template_hidden_path, template_JWT, template_CRLF
from OpenAI.get_vul_by_openAI import get_vul
import os
import re
import requests.exceptions
import urllib3
urllib3.disable_warnings()
import csv
import json
import hashlib


app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
apiKey = 'tp4c52en8ll0p89im4eojakbr8'

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_current_user():
    userid = session["userid"]
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE userid = ?',(userid,)).fetchone()
    conn.commit()
    conn.close()
    return user

def hash_password(password):
    hash_object = hashlib.sha256()
    hash_object.update(password.encode('utf-8'))
    hashed_password = hash_object.hexdigest()
    return hashed_password

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if session["userid"] is not None:
            return redirect(url_for('dashboard'))
    except:
        print('a')
    if request.method == "POST":
        details = request.form
        #retriving details from the form
        username = details['username'] 
        password = details['password']

        password = hash_password(password)
        
        #creating a DB connection
        cur = get_db_connection()
        isactive = cur.execute('SELECT * FROM users WHERE username = ? AND isactive = ?',(username,0,)).fetchone()
        if isactive is not None:
            msg = 'Account is inactive'
            return render_template('login.html',msg=msg)
        account = cur.execute('SELECT * FROM users WHERE username = ? AND password = ?',(username,password,)).fetchone()
        cur.commit()
        cur.close()
        if account is not None:
            session["userid"] = account["userid"]
            return redirect(url_for('dashboard'))
        else:
            msg = 'Username or password is incorrect'
            return render_template('login.html',msg=msg)
    return render_template('login.html')
@app.route("/myprofile")
def profile():
    msg =''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    cur = get_db_connection()
    userid = session["userid"]
    user = cur.execute('SELECT * FROM users WHERE userid = ?',(userid,)).fetchall()
    projects = cur.execute('SELECT * FROM users,projects WHERE (username = manager OR username = pentester) AND userid = ?',(userid,)).fetchall()
    cur.commit()
    cur.close()
    if user is not None:
        return render_template('profile.html',currentuser=currentuser,projects=projects,user=user,msg=msg)
    else:
        return 'user not exist'

@app.route('/add-user', methods=('GET', 'POST'))
def add_user():
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    conn = get_db_connection()
    msg = ''
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        password = request.form['password']
        confirmpassword = request.form['confirmpassword']
        currentuser= get_current_user()
        create_by = currentuser["username"]
        isactive = 1
        exist = conn.execute('SELECT * FROM users WHERE username = ?',(username,)).fetchone()
        msg = ''
        if not username or not role or not password or not confirmpassword:
            msg = 'Something is missing!'
        else:
            if exist is not None:
                msg = 'Username existed'
            else:
                if confirmpassword != password:
                    msg = 'Password not match!'
                else:
                    msg = 'Add user successfully'
                    hashed_password = hash_password(password)
                    conn = get_db_connection()
                    conn.execute('INSERT INTO users (username,password,join_date,role,update_date,isactive,create_by) VALUES (?,?,?,?,?,?,?)',
                            (username,hashed_password,datetime.today().strftime('%Y-%m-%d'),role,datetime.today().strftime('%Y-%m-%d'),isactive,create_by))
                    conn.commit()
                    conn.close()
                    return redirect(url_for('showuser'))
    return render_template('add_user.html',msg=msg,currentuser=currentuser)
@app.route("/search_user", methods=['GET', 'POST'])
def search_user():
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    msg = ''
    if request.method == 'GET':
        username = request.args.get('username')
        conn = get_db_connection()
        users = conn.execute("SELECT * FROM users WHERE username LIKE ?", ('%' + username + '%',)).fetchall()
        conn.commit()
        conn.close()
        if users is not None:
            return render_template('show_user.html',currentuser=currentuser, users = users ,msg = msg)
        else: 
            msg = 'User not found'
            return render_template('show_user.html',currentuser=currentuser, users = users ,msg = msg)
        
@app.route("/change-pass", methods=['GET', 'POST'])
def changepwd():
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if request.method == 'POST':
        currentpasswd = currentuser["password"]
        oldpassword = request.form['oldpassword']
        newpassword = request.form['newpassword']
        repassword = request.form['repassword']

        oldpassword = hash_password(oldpassword)

        if newpassword != repassword:
            msg='Passwords do not match'
            return render_template('changes_pass.html', msg = msg)
        if oldpassword != currentpasswd:
            msg='Passwords wrong'
            return render_template('changes_pass.html', msg = msg)
        msg = 'update password successfully'
        hashed_newpassword = hash_password(newpassword)
        conn = get_db_connection()
        exist = conn.execute('UPDATE users SET password=? WHERE userid = ?',(hashed_newpassword,currentuser["userid"])).fetchone()
        user = conn.execute('SELECT * FROM users WHERE userid = ?',(currentuser["userid"],)).fetchall()
        conn.commit()
        projects = conn.execute('SELECT * FROM users,projects WHERE (username = manager OR username = pentester) AND userid = ?',(currentuser["userid"],)).fetchall()
        conn.close()
        return render_template('profile.html',projects=projects,currentuser=currentuser,user=user,msg = msg)
    return render_template('changes_pass.html',currentuser=currentuser, msg = msg)
@app.route("/about-us")
def about_us():
    return render_template('about_us.html')
@app.route("/logout")
def logout():
    session["userid"] = None
    return redirect(url_for('login'))
@app.route("/",methods=('GET', 'POST'))
def index():
    try :
        if session["userid"] is not None:
            return redirect(url_for('dashboard'))
    except:
        print('a')
    if request.method == "POST":
        details = request.form
        #retriving details from the form
        username = details['username'] 
        password = details['password']
        
        #creating a DB connection
        cur = get_db_connection()
        isactive = cur.execute('SELECT * FROM users WHERE username = ? AND isactive = ?',(username,0,)).fetchone()
        if isactive is not None:
            msg = 'Account is inactive'
            return render_template('login.html',msg=msg)
        account = cur.execute('SELECT * FROM users WHERE username = ? AND password = ?',(username,password,)).fetchone()
        cur.commit()
        cur.close()
        if account is not None:
            session["userid"] = account["userid"]
            return redirect(url_for('dashboard'))
        else:
            msg = 'Username or password is incorrect'
            return render_template('login.html',msg=msg)
    return render_template('login.html')
@app.route("/dashboard")
def dashboard():
    try: 
        if session["userid"] == None:
            return redirect(url_for('login'))
    except:
        print('a')
    if session["userid"] is not None:
        currentuser = get_current_user()
        conn = get_db_connection()
        critical = conn.execute('SELECT count(bugid) FROM bugs WHERE risk = ? AND pentester = ?',('Critial',currentuser["username"],)).fetchone()
        total_critical = critical['count(bugid)']
        conn.commit()
        
        high = conn.execute('SELECT count(bugid) FROM bugs WHERE risk = ? AND pentester = ?',('High',currentuser["username"],)).fetchone()
        total_high = high['count(bugid)']
        conn.commit()
        
        medium = conn.execute('SELECT count(bugid) FROM bugs WHERE risk = ? AND pentester = ?',('Medium',currentuser["username"],)).fetchone()
        total_medium = medium['count(bugid)']
        conn.commit()
        
        low = conn.execute('SELECT count(bugid) FROM bugs WHERE risk = ? AND pentester = ?',('Low',currentuser["username"],)).fetchone()
        total_low = low['count(bugid)']
        conn.commit()
        
        info = conn.execute('SELECT count(bugid) FROM bugs WHERE risk = ? AND pentester = ?',('Informational',currentuser["username"],)).fetchone()
        total_info = info['count(bugid)']
        conn.commit()
        
        bugs = conn.execute('SELECT name,count(bugid) FROM bugs WHERE pentester = ? group by name',(currentuser["username"],)).fetchall()
        conn.commit()
    else:
        render_template('base.html')
    return render_template('dashboard.html',total_critical=total_critical,total_high=total_high,total_medium=total_medium,total_low=total_low,total_info=total_info,bugs=bugs)
@app.route("/enableaccount", methods=('GET', 'POST'))
def enableaccount():
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    msg = ''
    if request.method == 'POST':
        conn = get_db_connection()
        userid = request.form['userid']
        exist = conn.execute('UPDATE users set update_by = ?,isactive = ? WHERE userid = ?',(currentuser["username"],1,userid,)).fetchone()
        conn.commit()
        conn.close()
        msg = ''
        if exist is None:
            msg ='Update sucessfully'
        else:
            msg = 'An error occurred while updateing'
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.commit()
    conn.close()
    return render_template('show_user.html', currentuser=currentuser,users=users,msg=msg)
@app.route('/usermanager', methods=('GET', 'POST'))
def showuser():
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    ### DEACTIVE USER
    if request.method == 'POST':
        conn = get_db_connection()
        userid = request.form['userid']
        exist = conn.execute('UPDATE users set update_by = ?,isactive = ? WHERE userid = ?',(currentuser["username"],0,userid,)).fetchone()
        conn.commit()
        conn.close()
        msg = ''
        if exist is None:
            msg ='Update sucessfully'
        else:
            msg = 'An error occurred while Updateing'
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.commit()
    conn.close()
    return render_template('show_user.html',currentuser=currentuser, users=users,msg=msg)
@app.route('/leaderboard', methods=('GET', 'POST'))
def leaderboard():
    if session["userid"] == None:
        return redirect(url_for('login'))
    conn = get_db_connection()
    data = {}
    users = conn.execute('SELECT username FROM users').fetchall()
    totals = conn.execute("SELECT bugs.pentester,count(bugid),testdate FROM bugs,requests WHERE requests.requestid = bugs.requestid AND strftime('%Y-%m', testdate)  = ? group by bugs.pentester ", (datetime.today().strftime('%Y-%m'),)).fetchall()
    #datas = sorted(totals, key=lambda x: x['cound(bugid)'], reverse=True)
    current_month = datetime.now().month
    current_year = datetime.now().year
    datas = sorted(totals, key=lambda x: x[1], reverse=True)
    return render_template('leaderboard.html',users=users,datas=datas,current_month=current_month,current_year=current_year)
@app.route('/edituser/<int:id>', methods=('GET', 'POST'))
def edituser(id):
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] != 'Administrator':
        return render_template('403.html',)
    msg=''
    if session["userid"] == None:
        return redirect(url_for('login'))
    conn = get_db_connection()
    update = conn.execute('SELECT * FROM users WHERE userid = ?',(id,)).fetchall()
    conn.commit()
    conn.close()
    if update is not None:
        if request.method == 'POST':
            role = request.form['role']
            update_date = datetime.today().strftime('%Y-%m-%d')
            update_by = currentuser["username"]
            if not role:
                role = currentuser['role']
            else:
                conn = get_db_connection()
                exist = conn.execute('UPDATE users SET role=?,update_date=?,update_by=?WHERE userid = ?',(role,update_date,update_by,id,)).fetchone()
                conn.commit()
                conn.close()
                if exist is not None:
                    msg='Cannot edit user'
                else:
                    msg='Edit successfully'
                    conn = get_db_connection()
                    users = conn.execute('SELECT * FROM users').fetchall()
                    update = conn.execute('SELECT * FROM users WHERE userid = ?',(id,)).fetchall()
                    conn.commit()
                    conn.close()
                    return render_template('show_user.html', currentuser=currentuser,users=users,msg=msg)
        return render_template('edit_user.html',currentuser=currentuser, update=update,msg=msg)
        
        
## PROJECT ##
        
        
@app.route('/projectmanager', methods=('GET', 'POST'))
def showproject():
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    conn = get_db_connection()
    projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
    allprojects = conn.execute('SELECT * FROM projects').fetchall()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.commit()
    conn.close()
    return render_template('show_project.html', allprojects=allprojects,currentuser=currentuser,projects=projects,users=users,msg=msg)
@app.route('/cookies-config/<int:id>', methods=('GET', 'POST'))
def cookies_config(id):
    conn = get_db_connection()
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    role = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    currentuser = get_current_user()
    if currentuser["username"] != role["pentester"]:
        if currentuser["username"] == role["manager"]:
            print("")
        elif currentuser["role"] == 'Administrator':
            print("")
        else:
            return render_template('403.html',)
    if request.method == 'POST':
        loginurl = request.form["loginurl"]
        userparam = request.form['usernameparameter']
        passparam = request.form['passwordparameter']
        csrfparam = request.form['csrfparam']
        username = request.form['username']
        password = request.form['password']
        isconfig = 1
        conn.execute('INSERT INTO sessions (projectid,loginurl,userparam,passparam,csrfparam,username,password) VALUES (?,?,?,?,?,?,?)',
                    (id,loginurl,userparam,passparam,csrfparam,username,password))
        conn.commit()
        conn.execute('UPDATE projects SET isconfig=? WHERE projectid=?',
                        (isconfig,id,)).fetchone()
        conn.commit()
        conn = get_db_connection()
        projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
        allprojects = conn.execute('SELECT * FROM projects').fetchall()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.commit()
        conn.close()
        return render_template('show_project.html',allprojects=allprojects, currentuser=currentuser,projects=projects,users=users,msg=msg)
    conn.close()
    return render_template('config.html')
@app.route('/cookies-update/<int:id>', methods=('GET', 'POST'))
def cookies_update(id):
    msg = ''
    conn = get_db_connection()
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    role = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    if currentuser["username"] != role["pentester"]:
        if currentuser["username"] == role["manager"]:
            print("")
        elif currentuser["role"] == 'Administrator':
            print("")
        else:
            return render_template('403.html',)
    
    if request.method == 'POST':
        loginurl = request.form["loginurl"]
        userparam = request.form['usernameparameter']
        passparam = request.form['passwordparameter']
        csrfparam = request.form['csrfparam']
        username = request.form['username']
        password = request.form['password']
        isconfig = 1
        conn.execute('UPDATE sessions SET loginurl = ? ,userparam = ?,passparam = ?,csrfparam =?, username = ?,password = ? WHERE projectid = ?',
                    (loginurl,userparam,passparam,csrfparam,username,password,id,))
        conn.commit()
        conn.execute('UPDATE projects SET isconfig=? WHERE projectid=?',
                        (isconfig,id,)).fetchone()
        conn.commit()
        conn = get_db_connection()
        projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
        allprojects = conn.execute('SELECT * FROM projects').fetchall()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.commit()
        conn.close()
        return render_template('show_project.html',allprojects=allprojects, currentuser=currentuser,projects=projects,users=users,msg=msg)
    projectdata = conn.execute('SELECT * FROM sessions WHERE projectid = ?',(id,)).fetchone()
    conn.commit()
    conn.close()
    return render_template('session_update.html',projectdata=projectdata)
@app.route('/editproject/<int:id>', methods=('GET', 'POST'))
def editproject(id):
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    conn = get_db_connection()
    if currentuser["role"] == 'Pentester':
        return render_template('403.html',)
    role = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    if currentuser["role"] != 'Administrator':
        if currentuser["username"] != role["manager"]:
            return render_template('403.html',)
    projects = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchall()
    project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    users = conn.execute('SELECT * FROM users').fetchall()
    if request.method == 'POST':
        projectname = request.form['projectname']
        target = request.form['target']
        manager = request.form['manager']
        pentester = request.form['pentester']
        status = request.form['status']
        exist = conn.execute('SELECT * FROM projects WHERE projectname = ?',(projectname,)).fetchone()
        if exist is not None:
            msg = 'Project Name already existed'
            return render_template('edit_project.html', projects=projects,users=users,msg=msg)
        if not projectname:
            projectname = project["projectname"]
        if not target:
            target = project["target"]
        if not manager:
            manager = project["manager"]
        if not pentester:
            pentester = project["pentester"]
        if not status:
            status = project["status"]
        msg = 'UPDATE Project successfully'
        conn = get_db_connection()
        conn.execute('UPDATE projects SET projectname=?,target=?,manager=?,pentester=?,status=? WHERE projectid=?',
                        (projectname,target,manager,pentester,status,id,)).fetchone()
        conn.commit()
        conn.close()
        return redirect(url_for('showproject'))
    
    return render_template('edit_project.html',currentuser=currentuser, projects=projects,users=users,msg=msg)
@app.route('/deleteproject/<int:id>', methods=('GET', 'POST'))
def deleteproject(id):
    msg = ''
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] == 'Pentester':
        return render_template('403.html',)
    conn = get_db_connection()
    update = conn.execute('DELETE FROM projects WHERE projectid = ?',(id,)).fetchall()
    update_requests = conn.execute('DELETE FROM requests WHERE projectid =?',(id,)).fetchall()
    projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
    allprojects = conn.execute('SELECT * FROM projects').fetchall()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.commit()
    conn.close()
    return render_template('show_project.html',allprojects=allprojects,currentuser=currentuser, projects=projects,users=users,msg=msg)
@app.route('/create-project', methods=('GET', 'POST'))
def add_project():
    msg = ''
    conn = get_db_connection()
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    if currentuser["role"] == 'Pentester':
        return render_template('403.html',)
    users = conn.execute('SELECT * FROM users').fetchall()
    if request.method == 'POST':
        projectname = request.form['projectname']
        startdate = request.form['startdate']
        target = request.form['target']
        manager = request.form['manager']   
        pentester = request.form['pentester']
        status = 'Pending'
        exist = conn.execute('SELECT * FROM projects WHERE projectname = ?',(projectname,)).fetchone()
        if exist is not None:
            msg = 'Project Name already existed'
            return render_template('add_project.html',users=users,msg=msg)
        else:
            msg = 'Create Project successfully'
            conn = get_db_connection()
            conn.execute("INSERT INTO projects (projectname,startdate,target,create_by,manager,pentester,status) VALUES (?,?,?,?,?,?,?)",
                        (projectname,startdate,target,currentuser["username"],manager,pentester,status))
            conn.commit()
            projects = conn.execute('SELECT * FROM projects where pentester = ? OR manager = ?',(currentuser["username"],currentuser["username"],)).fetchall()
            allprojects = conn.execute('SELECT * FROM projects').fetchall()
            conn.commit()
            conn.close()
            return render_template('show_project.html',allprojects=allprojects,currentuser=currentuser, projects = projects,users=users,msg = msg)
    return render_template('add_project.html',currentuser=currentuser,users=users,msg=msg)
@app.route("/search_project", methods=['GET', 'POST'])
def search_project():
    
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    msg = ''
    if request.method == 'GET':
        projectname = request.args.get('projectname')
        conn = get_db_connection()
        projects = conn.execute('SELECT * FROM projects WHERE projectname like ?',('%'+projectname+'%',)).fetchall()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.commit()
        conn.close()
        if projects is not None:
            return render_template('show_project.html', currentuser=currentuser,projects = projects,users=users ,msg = msg)
        else: 
            msg = 'Project not found'
            return render_template('show_project.html',currentuser=currentuser, projects = projects,users=users,msg = msg)
@app.route('/project-detail/<int:id>', methods=('GET', 'POST'))
def project_detail(id):
    msg = ''
    conn = get_db_connection()
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    if currentuser["username"] != project["pentester"]:
        if currentuser["username"] == project["manager"]:
            print("")
        elif currentuser["role"] == 'Administrator':
            print("")
        else:
            return render_template('403.html',)
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users',).fetchall()
    havebugs = conn.execute('SELECT * FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ? AND bugs.requestid in (SELECT requestid FROM bugs) GROUP BY bugs.requestid',(id,)).fetchall()
    requests = conn.execute('SELECT * FROM requests WHERE projectid = ?',(id,)).fetchall()
    total = conn.execute('SELECT count(requestid) FROM requests WHERE projectid = ?',(id,)).fetchone()
    totalrequest = total["count(requestid)"]
    done = conn.execute('SELECT count(requestid) FROM requests WHERE status = ? AND projectid = ?',("Done",id,)).fetchone()
    donerequest = done["count(requestid)"]
    remain = total["count(requestid)"] - done["count(requestid)"]
    if remain == 0 and totalrequest != 0:
        updateprj = conn.execute('UPDATE projects SET status = ?,enddate= ? WHERE projectid = ?',("Done",datetime.today().strftime('%Y-%m-%d'),id,))
    conn.commit()
    
    bugs = conn.execute('SELECT bugs.name,count(bugid),risk,detail FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ? GROUP BY bugs.name',(id,)).fetchall()
    conn.commit()
    conn.close()
    return render_template('project_detail.html',bugs=bugs,currentuser=currentuser,havebugs=havebugs,users=users,project=project,totalrequest=totalrequest,donerequest=donerequest,remain=remain,requests=requests,msg=msg)
@app.route('/bug-detail/<int:id>', methods=('GET', 'POST'))
def bug_detail(id):
    msg = ''
    conn = get_db_connection()
    if session["userid"] == None:
        return redirect(url_for('login'))
    currentuser = get_current_user()
    conn = get_db_connection()
    requesturl = conn.execute('SELECT requesturl FROM requests WHERE requestid = ?',(id,)).fetchone()
    bugs = conn.execute('SELECT * FROM bugs WHERE bugurl LIKE ?',(requesturl["requesturl"],)).fetchall()
    return render_template('bug_detail.html',request=request,currentuser=currentuser,bugs=bugs,msg=msg)

@app.route('/call_chatGPT/<int:id>', methods=('GET', 'POST'))
def call_chatGPT(id):
    try:
        msg = ''
        currentuser = get_current_user()
        conn = get_db_connection()
        target = conn.execute('SELECT * FROM requests WHERE requestid = ?',(id,)).fetchone()
        conn.commit()
        projectid = target["projectid"]
        check = conn.execute('SELECT * FROM projects WHERE projectid = ?',(projectid,)).fetchone()
        if currentuser["username"] != check["pentester"]:
            if currentuser["username"] == check["manager"]:
                print("")
            elif currentuser["role"] == 'Administrator':
                print("")
            else:
                return render_template('403.html',)
        requesturl = target["requesturl"]
        conn = get_db_connection()
        ischatGPT = 1
        conn.execute('UPDATE requests SET ischatGPT= ? WHERE requestid=?',
                            (ischatGPT,id,)).fetchone()
        conn.commit()
        # Call ChatGPT generate testcase
        list_vul = get_vul(target["request"], target["response"])
        conn = get_db_connection()
        conn.execute('UPDATE requests SET testcase=? WHERE requestid=?',
                            (list_vul,id,)).fetchone()
        conn.commit()
        conn = get_db_connection()
        total_vunl = conn.execute('SELECT count(bugid) FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ?',(projectid,)).fetchone()
        project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(projectid,)).fetchone()
        requests = conn.execute('SELECT * FROM requests WHERE projectid = ?',(projectid,)).fetchall()
        users = conn.execute('SELECT * FROM users',).fetchall()
        total = conn.execute('SELECT count(requestid) FROM requests WHERE projectid = ?',(projectid,)).fetchone()
        totalrequest = total["count(requestid)"]
        done = conn.execute('SELECT count(requestid) FROM requests WHERE status = ? AND projectid = ?',("Done",projectid,)).fetchone()
        donerequest = done["count(requestid)"]
        remain = total["count(requestid)"] - done["count(requestid)"]
        conn.commit()
        bugs = conn.execute('SELECT bugs.name,count(bugid),risk FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ? GROUP BY bugs.name',(target["projectid"],)).fetchall()
        conn.commit()
        conn.close()
        return render_template('project_detail.html',bugs=bugs,currentuser=currentuser,users=users,project=project,totalrequest=totalrequest,donerequest=donerequest,remain=remain,requests=requests,msg=msg)
    except Exception as e:
        print("The error is: ",e)
        return render_template("404.html")
    
@app.route('/activescan/<int:id>', methods=('GET', 'POST'))
def activescan(id):
    try:
        msg = ''
        currentuser = get_current_user()
        conn = get_db_connection()
        target = conn.execute('SELECT * FROM requests WHERE requestid = ?',(id,)).fetchone()
        conn.commit()
        projectid = target["projectid"]
        check = conn.execute('SELECT * FROM projects WHERE projectid = ?',(projectid,)).fetchone()
        if currentuser["username"] != check["pentester"]:
            if currentuser["username"] == check["manager"]:
                print("")
            elif currentuser["role"] == 'Administrator':
                print("")
            else:
                return render_template('403.html',)
        requesturl = target["requesturl"]
        conn = get_db_connection()
        isscan = 1
        conn.execute('UPDATE requests SET isscan= ?,status = ?,pentester=?,testdate = ? WHERE requestid=?',
                            (isscan,"Done",currentuser["username"],datetime.today().strftime('%Y-%m-%d'),id,)).fetchone()
        conn.commit()

        request_have_bug = 0
        scan = UnauthenScanHeaders(target["requesturl"])

        method = target["method"]
        if "Frame-Options" in target["testcase"]:
            print("Scan X-Frame-Options -----------------------------------------------------------")
            xframe = scan.scan_xframe()
            if xframe == True:
                XFrame(id, target["requesturl"], currentuser['username'], method)
        if "HSTS" in target["testcase"]:
            print("Scan Security Headers (HSTS) ---------------------------------------------------")
            hsts = scan.scan_hsts()
            if hsts == True:
                HSTS(id, target["requesturl"], currentuser['username'], method)
        if "CSP" in target["testcase"]:
            print("Scan Security Headers (CSP) ----------------------------------------------------")
            policy = scan.scan_policy()
            if policy == True:
                CSP(id, target["requesturl"], currentuser['username'], method)
        if "Server" in target["testcase"]:
            print("Scan Server Version Information ------------------------------------------------")
            server = scan.scan_server()
            if server == True:
                Server_infor(id, target["requesturl"], currentuser['username'], method)
        if "Secure" in target["testcase"]:
            print("Scan Cookie Secure -------------------------------------------------------------")
            cookiesecure = has_secure_attribute(target["response"])
            if "not secure" in cookiesecure:
                Cookie_secure(id, target["requesturl"], currentuser['username'], method)
        if "HttpOnly" in target["testcase"]:
            print("Scan Cookie HttpOnly -----------------------------------------------------------")
            cookiehttp = has_httponly_attribute(target["response"])
            if "not httponly" in cookiehttp:
                Cookie_httponly(id, target["requesturl"], currentuser['username'], method)

        number_param = len(target["haveparam"].split(','))

        if "XSS" in target["testcase"]:
            print("Scan XSS -----------------------------------------------------------------------")
            print(target["haveparam"])
            content_XSS = scan_XSS(target["requesturl"], number_param)
            print(content_XSS)
            if content_XSS is None:
                print("No XSS found.")
            elif "No XSS" not in content_XSS:
                template_XSS(id, target["requesturl"], currentuser['username'], content_XSS, method)

        if "JWT" in target["testcase"]:
            print("Check JWT ----------------------------------------------------------------------")
            content_JWT = scan_JWT_Token(target["request"])
            if "Can not" in content_JWT:
                print("Can not crack JWT.")
            if "No JWTs" in content_JWT:
                print("No JWTs found in the request.")
            if is_jwt_used(target["request"]) is not None:
                if is_jwt_used(target["request"]) in content_JWT:
                    print(content_JWT)
                    template_JWT(id, target["requesturl"], currentuser['username'], content_JWT, method)

        if "Hidden Paths" in target["testcase"]:
            print("Check Hidden Paths -------------------------------------------------------------")
            content_hiddenpath = scan_hidden_path(target["requesturl"])
            print(content_hiddenpath)
            if len(content_hiddenpath) != 0:
                template_hidden_path(id, target["requesturl"], currentuser['username'], content_hiddenpath, method)
            else:
                print("No Hidden Paths")
        if "Components" in target["testcase"]:
            print("Check components ---------------------------------------------------------------")
            content_component = scan_component(target["requesturl"])
            json_string = json.dumps(content_component)
            print(json_string)
            if len(content_component) != 0:
                template_component(id, target["requesturl"], currentuser['username'], json_string, method)
        if "CRLF" in target["testcase"]:
            print("Check CRLF injections ----------------------------------------------------------")
            content_CRLF = scan_crlf(target["requesturl"], target["method"])
            if len(content_CRLF) != 0:
                template_CRLF(id, target["requesturl"], currentuser['username'], content_CRLF, method)
            else:
                print("No CRLF vulnerability")

        if "Command" in target["testcase"]:
            print("Check OS Command injections ----------------------------------------------------")
            content_OSCommand = scan_OS_cmd(target["request"], number_param)
            print(content_OSCommand)
            if "No OS" not in content_OSCommand:
                template_OS_Command(id, target["requesturl"], currentuser['username'], content_OSCommand, method)
        if "SameSite" in target["testcase"]:
            print("Check SameSite Attributes ------------------------------------------------------")
            content_SameSite = has_same_site_attribute(target["response"])
            if "set to None" in content_SameSite:
                template_sameSite_attribute(id, target["requesturl"], currentuser['username'], content_SameSite, method)
        if "QL" in target["testcase"]:
            print("Check SQL injections -----------------------------------------------------------")
            content_SQLi = scan_SQLi(target["request"])
            if "Not Found" not in content_SQLi:
                template_SQLi(id, target["requesturl"], currentuser['username'], content_SQLi, method)
        if "JavaScript Code" in target["testcase"]:
            print("Check JavaScript Code ----------------------------------------------------------")
            content_JS = find_javascript_code(target["response"])
            if "Not Found" not in content_JS:
                template_find_script(id, target["requesturl"], currentuser['username'], content_JS, method)
        if "SSTI" in target["testcase"]:
            print("Check SSTI injections ----------------------------------------------------------")
            content_SSTI = scan_SSTI(target["method"], target["haveparam"], target["requesturl"])
            if "Not Found" not in content_SSTI:
                template_SSTI(id, target["requesturl"], currentuser['username'], content_SSTI, method)
        if "Comment" in target["testcase"]:
            print("Check HTML Comment -------------------------------------------------------------")
            content_cmt = find_comments(target["response"])
            if "Not Found" not in content_cmt:
                template_find_comment(id, target["requesturl"], currentuser['username'], content_cmt, method)
        if "Methods" in target["testcase"]:
            print("Check HTTP Methods -------------------------------------------------------------")
            content_http_method = check_http_method(target["requesturl"])
            if "Not Found" not in content_http_method:
                template_http_method(id, target["requesturl"], currentuser['username'], content_http_method, method)
        if "HTTPS" in target["testcase"]:
            print("Check HTTP/HTTPS ---------------------------------------------------------------")
            content_http = check_http_https(target["requesturl"])
            if "Allow HTTP" in content_http:
                template_check_http_https(id, target["requesturl"], currentuser['username'], content_http, method)
        if "Cross" in target["testcase"]:
            print("Check Cross Domain Policy ------------------------------------------------------")
            content_CORS = scan_CORS(target["request"], target["requesturl"])
            print(content_CORS)
            if "No misconfigurations" not in content_CORS:
                template_CORS(id, target["requesturl"], currentuser['username'], content_CORS, method)
        if "Directory" in target["testcase"]:
            print("Check Path Traversal -----------------------------------------------------------")
            flag, content_path_travel = unau_path_travel_scan(target["requesturl"])
            print(content_path_travel)
            if flag:
                template_path_travel(id, target["requesturl"], currentuser['username'], content_path_travel, method)

        if request_have_bug == 1:
            conn3 = get_db_connection()
            conn3.execute('UPDATE requests SET bug = ? WHERE requestid= ?',
                                ("Bug Found",id,)).fetchone()
            conn3.commit()
            conn3.close()

        conn = get_db_connection()
        total_vunl = conn.execute('SELECT count(bugid) FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ?',(projectid,)).fetchone()
        conn.execute('UPDATE projects SET vunls=? WHERE projectid=?',
                            (total_vunl["count(bugid)"],projectid,))
        project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(projectid,)).fetchone()
        requests = conn.execute('SELECT * FROM requests WHERE projectid = ?',(projectid,)).fetchall()
        users = conn.execute('SELECT * FROM users',).fetchall()
        total = conn.execute('SELECT count(requestid) FROM requests WHERE projectid = ?',(projectid,)).fetchone()
        totalrequest = total["count(requestid)"]
        done = conn.execute('SELECT count(requestid) FROM requests WHERE status = ? AND projectid = ?',("Done",projectid,)).fetchone()
        donerequest = done["count(requestid)"]
        remain = total["count(requestid)"] - done["count(requestid)"]
        conn.commit()
        bugs = conn.execute('SELECT bugs.name,count(bugid),risk FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ? GROUP BY bugs.name',(target["projectid"],)).fetchall()
        conn.commit()
        conn.close()
        return render_template('project_detail.html',bugs=bugs,currentuser=currentuser,users=users,project=project,totalrequest=totalrequest,donerequest=donerequest,remain=remain,requests=requests,msg=msg)
    except Exception as e:
        print("The error is: ",e)
        return render_template("404.html")
    

##########################################################################
########################## Import CSV ####################################
##########################################################################
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = './Upload'
ALLOWED_EXTENSIONS = {'csv'}  # Định dạng tệp được phép

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload/', methods=['GET'])
def upload_CSV():
    return render_template('upload.html')

@app.route('/upload/', methods=['POST'])
def upload_file():
    conn = get_db_connection()
    cursor = conn.cursor()

    id_value = request.form['projectid']
    # id_value = projectid

    uploaded_file = request.files['file']
    if uploaded_file.filename != '':
        # uploaded_file.save("/Upload/", uploaded_file.filename)
        filename = secure_filename(uploaded_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(file_path)

        # Read the CSV file and insert its contents into the database
        with open(file_path, 'r') as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                result = []
                result.append(id_value)
                for i in range(len(row)):
                    result.append(row[i])
                
                cursor.execute('INSERT INTO requests (projectid, request, requesturl, method, haveparam, response, status) VALUES ( ?, ?, ?, ?, ?, ?, ?)', result)

        # Commit the changes
        conn.commit()
        return redirect(url_for('dashboard'))
    return 'No file uploaded.'

@app.route('/project-detail/', methods=['POST'])
def edit_request():
    import base64
    req_id = request.form["requestid"]
    msg = ''
    currentuser = get_current_user()
    conn = get_db_connection()
    target = conn.execute('SELECT * FROM requests WHERE requestid = ?',(req_id,)).fetchone()
    conn.commit()
    projectid = target["projectid"]
    check = conn.execute('SELECT * FROM projects WHERE projectid = ?',(projectid,)).fetchone()
    if currentuser["username"] != check["pentester"]:
        if currentuser["username"] == check["manager"]:
            print("")
        elif currentuser["role"] == 'Administrator':
            print("")
        else:
            return render_template('403.html',)
        
    requesturl = target["requesturl"]
    conn = get_db_connection()
    decoded_output = request.form["decodedOutput"+req_id]

    encoded_bytes = base64.b64encode(decoded_output.encode('utf-8'))
    encoded_string = encoded_bytes.decode('utf-8')

    conn.execute('UPDATE requests SET request=? WHERE requestid = ?',(encoded_string,req_id)).fetchone()
    total_vunl = conn.execute('SELECT count(bugid) FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ?',(projectid,)).fetchone()
    project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(projectid,)).fetchone()
    requests = conn.execute('SELECT * FROM requests WHERE projectid = ?',(projectid,)).fetchall()
    users = conn.execute('SELECT * FROM users',).fetchall()
    total = conn.execute('SELECT count(requestid) FROM requests WHERE projectid = ?',(projectid,)).fetchone()
    totalrequest = total["count(requestid)"]
    done = conn.execute('SELECT count(requestid) FROM requests WHERE status = ? AND projectid = ?',("Done",projectid,)).fetchone()
    donerequest = done["count(requestid)"]
    remain = total["count(requestid)"] - done["count(requestid)"]
    conn.commit()
    bugs = conn.execute('SELECT bugs.name,count(bugid),risk FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ? GROUP BY bugs.name',(target["projectid"],)).fetchall()
    conn.commit()
    conn.close()
    return render_template('project_detail.html',bugs=bugs,currentuser=currentuser,users=users,project=project,totalrequest=totalrequest,donerequest=donerequest,remain=remain,requests=requests,msg=msg)

##########################################################################
########################## REPORT ########################################
##########################################################################
@app.route('/generate-report/<int:id>', methods=['GET'])
def download_report(id):
    conn = get_db_connection()
    currenuser = get_current_user()
    if session["userid"] == None:
        return redirect(url_for('login'))
    results = conn.execute('SELECT * FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ?',(id,)).fetchall()
    project = conn.execute('SELECT * FROM projects WHERE projectid = ?',(id,)).fetchone()
    total_vunl = conn.execute('SELECT count(bugid) FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ?',(id,)).fetchone()
    summarys = conn.execute('SELECT count(requests.requestid),count(bugid),name,bugurl,risk,bugsmethod,detail,impact,cweid,description,solution,reference,other,requesturl FROM requests,bugs WHERE requests.requestid = bugs.requestid AND projectid = ? GROUP BY name',(id,)).fetchall()
    securitilevel =''
    for result in results:
        if result['risk'] == "Infomational":
            securitilevel = result['risk']
    for result in results:
        if result['risk'] == "Low":
            securitilevel = result['risk']
    for result in results:
        if result['risk'] == "Medium":
            securitilevel = result['risk']
    for result in results:
        if result['risk'] == "High":
            securitilevel = result['risk']
    for result in results:
        if result['risk'] == "Critical":
            securitilevel = result['risk']

    pdf = FPDF()
    pdf.add_page()
    
    page_width = pdf.w - 2 * pdf.l_margin
    pdf.set_font('Times','B',14.0)
    pdf.cell(page_width, 0.0,' FINAL REPORT', align='C')
    pdf.ln(10)
    pdf.cell(page_width, 0.0, "I. Document Properties")
    pdf.ln(5)
    pdf.set_font('Times','B',13.0)
    pdf.cell(page_width, 0.0, "1. Scope of work")
    pdf.ln(5)
    pdf.set_font('Times','',12.0)
    th = pdf.font_size
    pdf.cell(page_width, th, "The scope of the penetration test was limited to the following target:")
    pdf.ln(5)
    th = pdf.font_size
    pdf.cell(page_width/3, th, 'Target ',border = 1)
    pdf.cell(page_width/1.5, th, project["target"],border = 1)
    pdf.ln(10)
    pdf.set_font('Times','B',13.0)
    pdf.cell(page_width, 0.0, "2. Executive Summary")
    pdf.ln(5)
    pdf.set_font('Times','',12.0)
    th = pdf.font_size
    pdf.cell(page_width, th, "The information of project is listed bellow:")
    pdf.ln(5)
    pdf.set_font('Times', '', 12)
    th = pdf.font_size
    # project info

    pdf.cell(page_width/3, th, 'Project Name ',border = 1)
    pdf.cell(page_width/1.5, th, project["projectname"],border = 1)
    pdf.ln(5)
    pdf.cell(page_width/3, th, 'Start Date ',border = 1)
    pdf.cell(page_width/1.5, th, str(project["startdate"]),border = 1)
    pdf.ln(5)
    pdf.cell(page_width/3, th, 'End Date ',border = 1)
    pdf.cell(page_width/1.5, th, str(project["enddate"]),border = 1)
    pdf.ln(5)
    pdf.cell(page_width/3, th, 'Project Manager ',border = 1)
    pdf.cell(page_width/1.5, th, project["manager"],border = 1)
    pdf.ln(5)
    pdf.cell(page_width/3, th, 'Project Penteser ',border = 1)
    pdf.cell(page_width/1.5, th,project["pentester"],border = 1)
    pdf.ln(5)
    pdf.cell(page_width/3, th, 'Total Vulnerabilities',border = 1)
    pdf.cell(page_width/1.5, th,str(total_vunl["count(bugid)"]),border = 1)
    pdf.ln(5)
    pdf.cell(page_width/3, th, 'Risk Level',border = 1)
    pdf.cell(page_width/1.5, th,securitilevel,border = 1)
    pdf.ln(5)
    
        
    pdf.set_font('Times','B',13.0)
    pdf.ln(10)
    pdf.cell(page_width, 0.0, "3. Summary of Findings")
    pdf.ln(5)
    pdf.set_font('Times','',12.0)
    th = pdf.font_size
    pdf.cell(page_width, th, "After performing the test on the target, we give the following summary results : ")
    pdf.ln(5)
    pdf.set_font('Times', '', 12)
    th = pdf.font_size
    
    pdf.set_font('Times', '', 12)
    th = pdf.font_size
    col_width = page_width/4
		
    pdf.ln(1)
		
    i = 1
    pdf.cell(page_width/13, th, "Index",border = 1,align='C')
    pdf.cell(page_width/1.4, th, "Bug name",border = 1,align='C')
    pdf.cell(page_width/7, th,'Risk',border = 1,align='C')
    pdf.cell(page_width/15, th,"Count",border = 1,align='C')
    pdf.ln(th)
    for row in summarys:
        pdf.cell(page_width/13, th, str(i),border = 1,align='C')
        pdf.cell(page_width/1.4, th, row['name'],border = 1)
        pdf.cell(page_width/7, th,row['risk'],border = 1)
        pdf.cell(page_width/15, th,str(row['count(bugid)']),border = 1,align='C')
        pdf.ln(th)
        i = i+1
    pdf.ln(10)        
    pdf.set_font('Times','B',14.0)
    pdf.cell(page_width, 0.0, "II. Bugs Detail")
    pdf.ln(5)
    k = 1
    w=0
    pdf.set_font('Times','',13.0)
    
    for row in summarys:
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/20, th, str(k)+".",'C')
        pdf.cell(page_width/1.2, th, row['name'])
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/5, th, "Totail Enpoint : ")
        pdf.set_font('Times','',13.0)
        pdf.cell(page_width/4, th, str(row['count(requests.requestid)']))
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/5, th, "Cweid: ")
        pdf.set_font('Times','',13.0)
        pdf.cell(page_width/4, th, str(row['cweid']))
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/5, th, "Risk: ")
        pdf.set_font('Times','',13.0)
        pdf.cell(page_width/5, th, row['risk'])
        pdf.ln(th)
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/5, th, "Enpoint: ")
        pdf.ln(th)
        conn = get_db_connection()
        bugurls = conn.execute('SELECT method,bugurl FROM bugs,requests WHERE requests.requestid = bugs.requestid AND projectid = ? AND bugs.name = ?',(id,row['name'],)).fetchall()
        pdf.set_font('Times','',13.0)
        for bugurl in bugurls:
            pdf.cell(page_width/50, th, '- ')
            pdf.multi_cell(0, th, bugurl['method'])
            pdf.multi_cell(0, th, bugurl["bugurl"])
            pdf.ln(th)
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/20, th, "Description: ")
        pdf.set_font('Times','',13.0)
        pdf.ln(th)
        pdf.multi_cell(0, th, str(row['description']))
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/20, th, "Solution : ")
        pdf.ln(th)
        pdf.set_font('Times','',13.0)
        pdf.multi_cell(0, th, row['solution'])
        pdf.ln(th)

        if row['impact'] is not None:
            pdf.set_font('Times','B',13.0)
            pdf.cell(page_width/20, th, "Impact : ")
            pdf.ln(th)
            pdf.set_font('Times','',13.0)
            pdf.multi_cell(0, th, row['impact'])
            pdf.ln(th)

        if row['detail'] is not None:
            pdf.set_font('Times','B',13.0)
            pdf.cell(page_width/20, th, "Detail : ")
            pdf.ln(th)
            pdf.set_font('Times','',13.0)
            pdf.multi_cell(0, th, row['detail'])
            pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(page_width/20, th, "Reference: ")
        pdf.ln(th)
        pdf.set_font('Times','',13.0)
        pdf.multi_cell(0, th, row['reference'])
        pdf.ln(th)
        
        pdf.set_font('Times','B',13.0)
        pdf.cell(0, th, "Other: ")
        pdf.ln(th)
        pdf.set_font('Times','',13.0)
        pdf.multi_cell(0, th, row['other'])
        pdf.ln(th)
        k = k + 1
    pdf.ln(10)
    pdf.set_font('Times','',10.0) 
    pdf.cell(page_width, 0.0, '- end of report -', align='C')
    return Response(pdf.output(dest='S').encode('latin-1'), mimetype='application/pdf', headers={'Content-Disposition':'attachment;filename=final_report.pdf'})


if __name__ == '__main__':
    app.run(debug=True)
