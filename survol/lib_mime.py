import os
import sys

try:
	import mimetypes
	mimelib_present = True
except ImportError:
	mimelib_present = False

def FilenameToMime(pathName):
	sys.stderr.write("FilenameToMime pathName=%s\n"%pathName)

	# On Linux, we want to read text files in the /proc filesystem
	if pathName.startswith("/proc/"):
		return ['text/plain', None]


	# Some types might not be well processed.
	fileName, fileExt = os.path.splitext(pathName)
	extUpper = fileExt.upper()

	if extUpper in [".LOG"]:
		return ['text/plain', None]

	if mimelib_present:
		# For example: ('text/plain', None)
		return mimetypes.guess_type( pathName )
	else:
		# Last chance if module is not available.
		# TODO: This can easily be completed.
		if extUpper in [".JPG",".JPEG"]:
			return ['image/jpeg', None]
		if extUpper in [".TXT"]:
			return ['image/jpeg', None]

		mime_stuff = [None]


