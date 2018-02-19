# #!/usr/bin/python
#
# """Display MIME content of a Windows resource"""
#
# # It receives as CGI arguments, the entity type which is "HttpUrl_MimeDocument", and the filename.
# # It must then return the content of the file, with the right MIME type,
#
# # CA VA ETRE UNE FONCTION APPELEE
# # par entity.py quand le type est windows/resource et mode=mime.
# # Comme ca on a le nommage.
# # et ca permet d afficher n imprte quel entoty comme du MIME.
# # Mais dans ces deux types, ajouter la fonction DisplayAsMime
#
# import os
# import sys
# import re
# import cgi
# import lib_common
# import lib_util
# import lib_win_resources
# from sources_types import win32
# from sources_types.win32 import resource as survol_win32_resource
#
# def Main():
# 	cgiEnv = lib_common.CgiEnv()
#
# 	arguments = cgi.FieldStorage()
# 	fileName = arguments["filename"].value
# 	groupName = arguments["groupname"].value
#
# 	sys.stderr.write("fileName=%s groupName=%s\n" % (fileName, groupName ) )
#
# 	mime_type = survol_win32_resource.mimeType
#
# 	tmpDirName = "C:\\tmp"
# 	resourceFilNam = survol_win32_resource.DispOneIcon(fileName,tmpDirName,groupName)
#
# 	try:
# 		lib_util.CopyFile( mime_type, resourceFilNam )
# 		# TODO: Should return a TmpFile which will be automatically removed.
# 		os.remove(resourceFilNam)
#
# 	except Exception:
# 		exc = sys.exc_info()[1]
# 		lib_common.ErrorMessageHtml("wim_resource_to_mime.py Reading resourceFilNam=%s, mime_type=%s caught:%s" % ( resourceFilNam, mime_type, str(exc) ) )
#
# if __name__ == '__main__':
# 	Main()
#
