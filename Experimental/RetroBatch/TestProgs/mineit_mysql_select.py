#!/usr/bin/python

# http://www.lokazionel.fr/fr/ressources/tutoriels/243-script-python-cgi-sur-hebergement-ovh.html
import cgi
import cgitb



# It does not use the same package depending on the platform.
try:
        # Windows
        import mysql.connector
        def MysqlMkInstance(aUser,aPass,aHost,aPort):
                # conn = mysql.connector.connect (user='primhilltcsrvdb1', password='xxx', host='primhilltcsrvdb1.mysql.db',buffered=True)
                if aPort:
                        conn = mysql.connector.connect (user=aUser, password=aPass, host=aHost,buffered=True,port = aPort)
                else:
                        conn = mysql.connector.connect (user=aUser, password=aPass, host=aHost,buffered=True)
                return conn
except ImportError:
        # Linux
        import MySQLdb
        def MysqlMkInstance(aUser,aPass,aHost,aPort):
                if aPort:
                        conn =  MySQLdb.connect(user=aUser, passwd=aPass, host=aHost, port = aPort)
                else:
                        conn =  MySQLdb.connect(user=aUser, passwd=aPass, host=aHost)
                return conn

conn = MysqlMkInstance('primhilltcsrvdb1', 'MySql123', 'primhilltcsrvdb1.mysql.db',None)

cursor = conn.cursor()

cursor.execute("show databases")

for databases in cursor:
	print(str(databases))


