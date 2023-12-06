import sqlite3
from datetime import datetime
connection = sqlite3.connect('database.db')

with open('schema.sql') as f:
    connection.executescript(f.read())

cur = connection.cursor()

cur.execute("INSERT INTO users (username,password,join_date,role,update_date,isactive,create_by) VALUES (?,?,?,?,?,?,?)",
            ('admin','admin','2022-04-15','Administrator',datetime.today().strftime('%Y-%m-%d'),1,'admin')
            )
cur.execute("INSERT INTO users (username,password,join_date,role,update_date,isactive,create_by) VALUES (?,?,?,?,?,?,?)",
            ('trong','trong',datetime.today().strftime('%Y-%m-%d'),'Pentester',datetime.today().strftime('%Y-%m-%d'),1,'admin')
            )
cur.execute("INSERT INTO users (username,password,join_date,role,update_date,isactive,create_by) VALUES (?,?,?,?,?,?,?)",
            ('long','long',datetime.today().strftime('%Y-%m-%d'),'Project Manager',datetime.today().strftime('%Y-%m-%d'),1,'admin')
            )
cur.execute("INSERT INTO projects (projectname,startdate,enddate,vunls,target,create_by,securitylevel,manager,pentester,status,login) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ('google project 2',datetime.today().strftime('%Y-%m-%d'),'2023-04-30',3,'http://127.0.0.1:3456','admin','medium','trong','long','doing',1)
            )
cur.execute("INSERT INTO projects (projectname,startdate,enddate,vunls,target,create_by,securitylevel,manager,pentester,status,login) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ('google project',datetime.today().strftime('%Y-%m-%d'),'2023-04-30',3,'https://public-firing-range.appspot.com','admin','high','trong','long','doing',0)
            )
connection.commit()
connection.close()