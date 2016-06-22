import sys
import json

# De facon generale, le user/pwd peut etre dans la ressource et donc la parser est dependant
# de la librairie, et donc eventuellement il faut charger une librairie et effectuer
# une fonction specifique. Autre cas, les URLs qui ont une facon standard de coder user/pass.
# En revanche, si le user/pass n est pas donne, on stocke de la meme facon.

# TODO: This is a hard-code.
filNam = "C:/Users/rchateau/SurvolCredentials.json"

def GetCredentials( credType, credName ):
	try:
		credentials = json.load( open(filNam) )
		print(credentials)
		arrType = credentials[credType]
		try:
			cred = arrType[credName]
			sys.stderr.write("GetCredentials credType=%s credName=%s usr=%s pass=%s\n" % (credType,credName,cred[0],cred[1]))
			return cred
		except KeyError:
			sys.stderr.write("GetCredentials Unknown name credType=%s credName=%s\n" % (credType,credName))
			return ('','')
	except KeyError:
		sys.stderr.write("GetCredentials Invalid type credType=%s credName=%s\n" % (credType,credName))
		return None
