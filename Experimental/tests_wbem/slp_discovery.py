#!/usr/bin/python

import os
import re
import sys

def slp_wbem_services():
	filter = "wbem"
	#  "/drives/c/Program Files (x86)/OpenSLP/slptool.exe"
	cmd = 'slptool findsrvs service:' + filter
	
	# TODO: DEBUGGING PURPOSE. FIX THIS.
	cmd = '"C:/Program Files (x86)/OpenSLP/slptool.exe" findsrvs service:' + filter

	stream = os.popen(cmd)
	# service:ftp.smallbox://192.168.100.1:21,65535
	for line in stream:
		matchObj = re.match( r'service:([^:]*):/?/?([^,]*)(.*)', line, re.M|re.I)
		if matchObj:
			yield {
					"name" : matchObj.group(1) , # "wbem"
					"url"  : matchObj.group(2) , # Starts with "http:" or "https:"
					"rest" : matchObj.group(3) }
		else:
			raise Exception("Invalid line "+line)
	resu = stream.close()
	
	if resu is not None:
		raise Exception("Error running "+cmd)



print("""Content-Type: text/html

<html>
<head></head>
<body>
""")

slplist = slp_wbem_services()

# print("<br>SLP sources:"+str(len(list(slplist)))+"<br")

print("<table>")
for sl in slplist:
    # {'url': 'https://192.168.1.83:5989', 'name': 'wbem', 'rest': ',65535'}
    print("<tr>")
    url = sl['url']
    print("<td><a href='connect?url=" + url + "'>" + url + "</a></td>")
    print("<td>" + sl['name'] + "</td>")
    print("<td>" + sl['rest'] + "</td>")
    print("</tr>")
print("</table>")

print("""
En fait, au lieu de se connecter explicitement a un serveiur WBEM,
il faudrait qu'ioin memorise une liste de serveuyrs et que a chaque fois' \
qu on se connecte a un objet, il y en ait une recherche
sur les erveurs WBEM connus.

Ce qu on peut faire ici est exploration et mise a jour de la liste
des serveurs, entrer les mots de passe etc.
Valider/invalider des serveurs.
Et quand on arrive sur un objet, on liste aussi un script qui va chercher cet objet sur le (ou les)
serveurs WBEM.
</body>
</html>
""")
