# TODO: This takes a bookmark file, and loads the content of urls.
# This is convenient for testing because successes and failures are counted.

import os
import sys
import signal
import socket

# This loads the module from the source, so no need to install it, and no need of virtualenv.
filRoot = ".."
if sys.path[0] != filRoot:
	sys.path.insert(0,filRoot)

# sys.stdout.write("Cwd=%s\n"%os.getcwd())
# sys.stdout.write("Path=%s\n"%sys.path)

import lib_bookmark

################################################################################
def GetContent(urlHRef,time_out):
	if sys.version_info >= (3,):
		from urllib.request import urlopen
		f = urlopen(urlHRef,None,time_out)
	else:
		from urllib2 import urlopen
		try:
			f = urlopen(urlHRef,timeout=time_out)
		# except socket.timeout as e:
		except:
			return None

	return f
################################################################################
counterSuccess = 0
counterFailure = 0
counterTimeout = 0

################################################################################
# This is set by a signal handler when a control-C is typed.
# It then triggers a clean exit, and creation of output results.
# This allows to monitor a running process, just for a given time
# without stopping it.
G_Interrupt = False

################################################################################

def RecursiveBookmarksProcessing(aDict, indent=0):
	global counterSuccess
	global counterFailure
	global counterTimeout

	if G_Interrupt:
		return False

	def Truncate(value):
		value = value.strip()
		strVal = str(value)
		return strVal

	try:
		theName = aDict["name"]
	except KeyError:
		theName = "No name"

	try:
		urlHRef = str(aDict["HREF"])
	except KeyError:
		# If no URL
		strVal = Truncate(theName)
		urlHRef = None

	# Temporary filter because this URL does not work anymore.
	if urlHRef and urlHRef.find("ddns") >= 0:
		urlHRef = None

	if urlHRef:
		sys.stdout.write("URL:%s\n"%urlHRef)
		try:
			f = GetContent(urlHRef,time_out=10)
			if not f:
				print("TIMEOUT")
				counterTimeout += 1
			else:
				myfile = f.read()
				sys.stdout.write("Content: %d bytes\n"%len(myfile))
				counterSuccess += 1
		except IOError:
			counterFailure += 1

	for keyDict in sorted(aDict.keys()):
		if keyDict not in ["children","HREF","name"]:
			valDict = aDict[keyDict]

	try:
		for oneObj in aDict["children"]:
			resu = RecursiveBookmarksProcessing(oneObj, indent+1)
			if not resu:
				break
	except KeyError:
		pass

	return True


def signal_handler(signal, frame):
	print('You pressed Ctrl+C!')
	global G_Interrupt
	G_Interrupt = True



def Main():
	# When waiting for a process, interrupt with control-C.
	signal.signal(signal.SIGINT, signal_handler)
	print('Press Ctrl+C to exit cleanly')

	try:
		filNam = sys.argv[1]
	except:
		# TODO: The directory should not be hard-coded.
		# filNam = r"C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\Docs\bookmarks_projets_survol_26_03_2018.html"
		filNam = r"C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\Docs\bookmarks.html"

	# Google bookmark is another possible source of bookmarks.
	# urlNam = "https://www.google.com/bookmarks/bookmarks.html?hl=fr"

	dictBookmarks = lib_bookmark.ImportBookmarkFile(filNam)

	RecursiveBookmarksProcessing(dictBookmarks)


	sys.stdout.write("Successes:%d\n"%counterSuccess)
	sys.stdout.write("Failures :%d\n"%counterFailure)
	sys.stdout.write("Time-outs:%d\n"%counterTimeout)

if __name__ == '__main__':
	Main()
