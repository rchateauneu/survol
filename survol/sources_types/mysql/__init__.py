"""
Software components related to mysql or mariadb database.
"""

def Graphic_colorbg():
	return "#66CCFF"

import lib_common

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
        import mysql.connector
        def MysqlMkInstance(aUser,aPass,aHost,aPort):
                # conn = mysql.connector.connect (user='primhilltcsrvdb1', password='xxx', host='primhilltcsrvdb1.mysql.db',buffered=True)
                if aPort:
                        conn = mysql.connector.connect (user=aUser, password=aPass, host=aHost,buffered=True,port = aPort)
                else:
                        conn = mysql.connector.connect (user=aUser, password=aPass, host=aHost,buffered=True)
                return conn
except ImportError:
        import MySQLdb
        def MysqlMkInstance(aUser,aPass,aHost,aPort):
                if aPort:
                        conn =  MySQLdb.connect(user=aUser, passwd=aPass, host=aHost, port = aPort)
                else:
                        conn =  MySQLdb.connect(user=aUser, passwd=aPass, host=aHost)
                return conn

# MysqlConnect(anInstance='192.168.0.17', aUser=u'linuxmysql', aPass=u'sqlmylinux')
def MysqlConnect(anInstance,aUser,aPass):
        (instanceHost,instancePort) = InstanceToHostPort(anInstance)
        conn = MysqlMkInstance( aUser, aPass, instanceHost, instancePort)
        return conn
