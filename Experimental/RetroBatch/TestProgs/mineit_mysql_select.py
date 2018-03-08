#!/usr/bin/python

# http://www.lokazionel.fr/fr/ressources/tutoriels/243-script-python-cgi-sur-hebergement-ovh.html
import cgi
import cgitb

#  "MySql": {
#    "primhillcomputers.com:primhilltcsrvdb1": [
#      "primhilltcsrvdb1",
#      "xxxxx"
#    ]
#  },
import mysql.connector

conn = mysql.connector.connect (user='primhilltcsrvdb1', password='****', host='primhilltcsrvdb1.mysql.db',buffered=True)
# conn = mysql.connector.connect (user='primhilltcsrvdb1', password='*****', host='primhillcomputers.com',buffered=True)

cursor = conn.cursor()

# databases = ("show databases")

cursor.execute("show databases")

for databases in cursor:
	print(str(databases))
################

# OK on OVH
if False:

	import MySQLdb
	conn = MySQLdb.connect(user='primhilltcsrvdb1', passwd='MySql123', host='primhilltcsrvdb1.mysql.db')

	cursor = conn.cursor()
	cursor.execute("show databases")
	for databases in cursor:
		print(str(databases))
	cursor.close()
	conn.close()

#('information_schema',)
#('primhilltcsrvdb1',)


# conn = MySQLdb.connect(host = "SERVEUR OVH souvent de type Mysqlx-x chez ovh",
#     user = "UTILISATEUR, souvent meme nom que la base chez ovh",
#     passwd = "MOT DE PASSE", db = "NOM DE LA BASE")
# cursor = conn.cursor()
#
# cursor.execute("SELECT * FROM table WHERE id=32")
# data = cursor.fetchone()
#
# i = 0
# while i <= 13:
# 	print "<p>", data[i], "</P>"
# 	i= i + 1
# print "</body></html>"


# https://stackoverflow.com/questions/3644839/python-mysql-module
# pip install mysql-connector-python

