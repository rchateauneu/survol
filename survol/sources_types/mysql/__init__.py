"""
Software components related to mysql or mariadb database.
"""

def Graphic_colorbg():
	return "#66CCFF"

def Graphic_colorfill():
	return "#66CCFF"

import lib_common

# Test commands for user creation.
# http://www.daniloaz.com/en/how-to-create-a-user-in-mysql-mariadb-and-grant-permissions-on-a-specific-database/
# CREATE DATABASE `mydb`;
# CREATE USER 'myuser' IDENTIFIED BY 'mypassword';
# GRANT USAGE ON *.* TO 'myuser'@localhost IDENTIFIED BY 'mypassword';
# GRANT USAGE ON *.* TO 'myuser'@'%' IDENTIFIED BY 'mypassword';
# GRANT ALL privileges ON `mydb`.* TO 'myuser'@localhost;
# FLUSH PRIVILEGES;
# SHOW GRANTS FOR 'myuser'@localhost;

def InstanceToHostPort(instanceName):
        instanceSplit = instanceName.split(":")
        instanceHost = instanceSplit[0]
        if len(instanceSplit) == 2:
                instancePort = int(instanceSplit[1])
        else:
                instancePort = None
        return (instanceHost,instancePort)

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

# MysqlConnect(anInstance='192.168.0.17', aUser=u'linuxmysql', aPass=u'yyyyyyy')
def MysqlConnect(anInstance,aUser,aPass):
        (instanceHost,instancePort) = InstanceToHostPort(anInstance)
        conn = MysqlMkInstance( aUser, aPass, instanceHost, instancePort)
        return conn
