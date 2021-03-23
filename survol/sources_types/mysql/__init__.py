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
def InstanceToHostPort(instance_name):
    instance_split = instance_name.split(":")
    instance_host = instance_split[0]
    if len(instance_split) == 2:
        instance_port = int(instance_split[1])
    else:
        instance_port = None
    return instance_host, instance_port


# It does not use the same package depending on the platform.
try:
    # Windows
    import mysql.connector
    def MysqlMkInstance(a_user, a_pass, a_host, a_port):
        # conn = mysql.connector.connect (user='primhilltcsrvdb1', password='xxx', host='primhilltcsrvdb1.mysql.db',buffered=True)
        if a_port:
            conn = mysql.connector.connect(user=a_user, password=a_pass, host=a_host, buffered=True, port=a_port)
        else:
            conn = mysql.connector.connect(user=a_user, password=a_pass, host=a_host, buffered=True)
        return conn
except ImportError:
    # Linux
    import MySQLdb
    def MysqlMkInstance(a_user, a_pass, a_host, a_port):
        if a_port:
            conn =  MySQLdb.connect(user=a_user, passwd=a_pass, host=a_host, port=a_port)
        else:
            conn =  MySQLdb.connect(user=a_user, passwd=a_pass, host=a_host)
        return conn


# MysqlConnect(anInstance='192.168.0.17', aUser=u'linuxmysql', aPass=u'yyyyyyy')
def MysqlConnect(an_instance, a_user, a_pass):
    instance_host, instance_port = InstanceToHostPort(an_instance)
    conn = MysqlMkInstance(a_user, a_pass, instance_host, instance_port)
    return conn
