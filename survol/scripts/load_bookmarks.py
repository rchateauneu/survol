# TODO: This takes a bookmark file, and loads the content of urls.
# This is convenient for testing because successes and failures are counted.

import os
import sys
import signal


# This loads the module from the source, so no need to install it, and no need of virtualenv.
fil_root = ".."
if sys.path[0] != fil_root:
	sys.path.insert(0, fil_root)


import lib_bookmark


################################################################################
def GetContent(urlHRef, time_out):
	if sys.version_info >= (3,):
		from urllib.request import urlopen
		f = urlopen(urlHRef,None,time_out)
	else:
		from urllib2 import urlopen
		try:
			f = urlopen(urlHRef, timeout=time_out)
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


def RecursiveBookmarksProcessing(a_dict, indent=0):
	global counterSuccess
	global counterFailure
	global counterTimeout

	if G_Interrupt:
		return False

	def Truncate(value):
		value = value.strip()
		str_val = str(value)
		return str_val

	try:
		the_name = a_dict["name"]
	except KeyError:
		the_name = "No name"

	try:
		urlHRef = str(a_dict["HREF"])
	except KeyError:
		# If no URL
		strVal = Truncate(the_name)
		urlHRef = None

	# Temporary filter because this URL does not work anymore.
	if urlHRef and urlHRef.find("ddns") >= 0:
		urlHRef = None

	if urlHRef:
		sys.stdout.write("URL:%s\n" % urlHRef)
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

	for key_dict in sorted(a_dict.keys()):
		if key_dict not in ["children", "HREF", "name"]:
			valDict = a_dict[key_dict]

	try:
		for one_obj in a_dict["children"]:
			resu = RecursiveBookmarksProcessing(one_obj, indent+1)
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
		fil_nam = sys.argv[1]
	except:
		fil_nam = os.path.join(os.path.dirname(__file__), "..", "..",  "Docs", "bookmarks.html")

	# Google bookmark is another possible source of bookmarks.
	# urlNam = "https://www.google.com/bookmarks/bookmarks.html?hl=fr"

	dict_bookmarks = lib_bookmark.ImportBookmarkFile(fil_nam)

	RecursiveBookmarksProcessing(dict_bookmarks)

	sys.stdout.write("Successes:%d\n" % counterSuccess)
	sys.stdout.write("Failures :%d\n" % counterFailure)
	sys.stdout.write("Time-outs:%d\n" % counterTimeout)


if __name__ == '__main__':
	Main()
