import os

try:
	import mimetypes
	mimelib_present = True
except ImportError:
	mimelib_present = False

def FilenameToMime(pathName):
	if mimelib_present:
		# For example: ('text/plain', None)
		return mimetypes.guess_type( pathName )
	else:
		# Last chance if module is not available.
		fileName, fileExt = os.path.splitext(pathName)
		# TODO: This can easily be completed.
		if fileExt.upper() in [".JPG",".JPEG"]:
			return ['image/jpeg', None]
		if fileExt.upper() in [".TXT",".LOG"]:
			return ['image/jpeg', None]

		mime_stuff = [None]


