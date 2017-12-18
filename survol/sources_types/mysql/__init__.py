# Things related to mysql or mariadb database.

def Graphic_colorbg():
	return "#66CCFF"

# It does not use the same package depending on the platform.
try:
        import mysql.connector
        def MysqlConnect(aHost,aUser,aPass):
                # conn = mysql.connector.connect (user='primhilltcsrvdb1', password='xxx', host='primhilltcsrvdb1.mysql.db',buffered=True)
                conn = mysql.connector.connect (user=aUser, password=aPass, host=aHost,buffered=True)
                return conn
except ImportError:
        import MySQLdb
        def MysqlConnect(aHost,aUser,aPass):
                conn =  MySQLdb.connect(user=aUser, passwd=aPass, host=aHost)
                return conn

