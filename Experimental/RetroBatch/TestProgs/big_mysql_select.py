#!/usr/bin/env python

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

# conn = MysqlMkInstance('primhilltcsrvdb1', '******', 'primhilltcsrvdb1.mysql.db',None)
# mysql> SELECT User FROM mysql.user; 
# conn = MysqlMkInstance('linuxmysql', '****', '127.0.0.1',None)
conn = MysqlMkInstance('root', '', '127.0.0.1',None)

cursor = conn.cursor()

# Databases are:
# 'information_schema',
# 'mysql',
# 'performance_schema',
# 'test',


cursor.execute("use mysql")
print("Database set")

cursor.execute("show tables")
for tabNam in cursor:
    print(str(tabNam))
print("End of tables")

# cursor.execute("describe user")
# for rowUser in cursor:
#	print(str(rowUser))

cursor.execute("select Host,User from user")
for rowUser in cursor:
    usrHost = rowUser[0]
    usrUser = rowUser[1]
    print(usrHost)
    print(str(rowUser))
print("End of users")

