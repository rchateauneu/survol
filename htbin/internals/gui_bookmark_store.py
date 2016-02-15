#!/usr/bin/python

try:
    import simplejson as json
except ImportError:
    import json

# import time
import urlparse
import os
import sys
import collections

# Ce code est absolument, hideux, tout ca pour editer un malheureux
# fichier. Je me demande si ca ne serait pas mieux de stocker
# nos bookmarks sous la forme d'un fichier RDF.
# Ca permettrait aussi d'afficher l'interdependance des liens
# sous la forme d'un graphe.

# ATTENTION: Ne devrait-on pas stocker separement les 
# URLs fabriquant du RDF (Et donc injectable dans un autre URL) ?

def tell_me_about(s):
	return (type(s), s)

# u'Marqu\xe9s r\xe9cemment',
# In fact, e9 is "e actute" in iso-8859-1
def fix_broken_unicode(s):
	# s = u'Marqu\xe9s r\xe9cemment', s.decode = <built-in method decode of unicode object at 0x83cd488>, ).encode undefined
	print tell_me_about(s)
	# return s.decode('iso-8859-1').encode('utf-8')
	# On a vu dans le json que cahrset=iso-8859-1 aka latin-1

	# 'ascii' codec can't encode character u'\xe9' in position 5: ordinal not in range(128) 
	# return s.decode('latin-1').encode('utf-8')

	# unknown encoding: unicode 
	# return s.decode('latin-1').encode('unicode')

	# 'ascii' codec can't encode character u'\xe9'
	# return s.decode('latin-1')

	toto = s.decode('latin-1')

	print toto
	return toto

	# return s.decode('utf-8','ignore')
	# return s.decode('iso-8859-1','ignore')
	# return s.decode('iso-8859-1','ignore').encode('ascii','ignore')
	# return s.decode('ascii','ignore').encode('ascii','ignore')
	# return s.decode('unicode')
	# return unicode(s.encode(u'utf-8'), u'iso-8859-1')
	# data="UTF-8 DATA"
	# udata=data.decode("utf-8")
	# asciidata=udata.encode("ascii","ignore")




def TryDate(data,key):
	try:
		date = data[key]
	except KeyError:
		return 0
	return date / 1000000

#def PrintAsJavascript(input):
#	if isinstance(input, dict):
#		# Dict comprehension not there in Python 2.5.2 ?
#		# return {PrintAsJavascript(key): PrintAsJavascript(value) for key, value in input.iteritems()}
#		result_dict = {}
#		for key, value in input.iteritems():
#			result_dict[ PrintAsJavascript(key) ] = PrintAsJavascript(value)
#		return result_dict
#	elif isinstance(input, list):
#		return [PrintAsJavascript(element) for element in input]
#	elif isinstance(input, unicode):
#		return input.encode('utf-8')
#	else:
#		return input

def ascii_encode_dict(data):
	result = {}
	for key, value in data.iteritems():
		result[ key.encode('ascii') ] = value
	return result

class Bookmark:
	def finish_init(self):
		# (u'place', '', u'folder=BOOKMARKS_MENU&folder=UNFILED_BOOKMARKS&fo ...
		u_p = urlparse.urlparse( self.m_url )
		# print u_p
		self.m_script = u_p.path
		print "Script=" + self.m_script

	@classmethod
	def fromArray(cls,bookmark):
		bk = Bookmark()
		bk.m_title = bookmark['title']
		bk.m_add_date = TryDate( bookmark, 'dateAdded') 
		bk.m_modified_date = TryDate( bookmark, 'lastModified' )
		# print bookmark
		bk.m_url = bookmark['uri']
		bk.finish_init()
		# print "fromArray"
		# print bk
		return bk

	def Affiche(self):
		print "URL=[" + self.m_url + "]"

# This is as modular as possible. These links could be stored in a netscape-format bookmark page,
# or as JSON data just like for chrome. Or anything else.
class BookmarkStore:

	def GetPathNam(self):
		return '/home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/htbin/internals/our_bookmarks.json'

	# Loads a JSON file containng the bookmarks and prints it as a Javascript variable.
	def LoadJson(self):
		Path = self.GetPathNam()
		# print "File=" + Path
		f=open(Path,'r')
		linelist = f.readlines()
		f.close()
		# Bug in Mozilla: Extra comma at the end of lists.
		clean_json = linelist[0].replace( ',]', ']' )
		return clean_json

	def SaveJson(self,con_list):
		Path = self.GetPathNam()
		outfile = open(Path, 'w')
		# json.dump(con_list,outfile)
		json.dump(con_list,outfile,encoding='latin-1')
		outfile.close()

	# The output of time.time() would be 1326378576.503359
	def TryDate(self,data,key):
		try:
			date = data[key]
		except KeyError:
			return 0
		return date / 1000000

	def JsonGetAux(self,con_list,title,margin):
		con_sub_list = con_list['children']
		for sub_bk in con_sub_list:
			try:
				uri = sub_bk['uri']
			except KeyError:
				uri = ''
			Tag = sub_bk['title']
			# print title + " =>" + margin + "sub_bk=" + Tag + " url=" + uri
			if sub_bk.has_key('children'):
				bookmarks = sub_bk['children']
				if bookmarks:
					bk = self.JsonGetAux(sub_bk,title,margin + "    ")
					if ( bk != "" ):
						return bk
			else:
				# Unicode equal comparison failed to convert both arguments to Unicode
				# if Tag.decode('utf-8') == title.decode('utf-8'):
				if Tag == title:
					return Bookmark.fromArray( sub_bk )
		return ""

	def ReallyLoad(self):
		clean_json = self.LoadJson()
		# Get Bookmarks Menu / Bookmarks toolbar / Tags / Unsorted Bookmarks
		# con_list = json.loads(clean_json)
		con_list = json.loads(clean_json,object_hook=ascii_encode_dict)
		return con_list

	def JsonGet(self,title):
		# print "JsonGet " + title

		# Get Bookmarks Menu / Bookmarks toolbar / Tags / Unsorted Bookmarks
		con_list = self.ReallyLoad()

		# We should it fact split the title based on a delimiter.
		return self.JsonGetAux(con_list,title,"    ")

	def JsonDelAux(self,con_list,title,margin):
		con_sub_list = con_list['children']
		for sub_bk in con_sub_list:
			try:
				uri = sub_bk['uri']
			except KeyError:
				uri = ''
			Tag = sub_bk['title']
			# print title + "=>" + margin + "sub_bk=" + Tag.encode('utf-8') + " url=" + uri
			# print "title=" + title
			# print "uri=" + uri
			# print "Tag=" + fix_broken_unicode(Tag)
			# print title + "=>" + margin + "sub_bk=" + fix_broken_unicode(Tag) + " url=" + uri
			if sub_bk.has_key('children'):
				bookmarks = sub_bk['children']
				if bookmarks:
					resu = self.JsonDelAux(sub_bk,title,margin + "==  ")
			else:
				# Unicode equal comparison failed to convert both arguments to Unicode
				# if Tag.decode('utf-8') == title.decode('utf-8'):
				if Tag == title:
					# print "Removed:" + title
					# List is passed by reference therefore modified.
					con_sub_list.remove(sub_bk)
					return 1
		return 0

	def JsonDel(self,title):
		# print "JsonDel " + title
		con_list = self.ReallyLoad()

		# We should it fact split the title based on a delimiter.
		result = self.JsonDelAux(con_list,title,"==  ")

		# print "========================"
		# print
		old_url = self.JsonGetAux(con_list,title,"    ")
		# print "old_url="
		# old_url.Affiche()
		self.SaveJson(con_list)
		if result == "":
			return "Title=" + title + ": NOT FOUND"
		else:
			return "Title=" + title + ": deleted"

	# We could also add a function to rename an element
	# and leave it as the same place, but we do not care yet.

	def JsonSetAux(self,con_list,title,bk,margin):
		con_sub_list = con_list['children']
		idx = 0
		for sub_bk in con_sub_list:
			try:
				uri = sub_bk['uri']
			except KeyError:
				uri = ''
			Tag = sub_bk['title']

			# Maybe this is an override
			if Tag == title:
				bk["index"] = idx
				con_sub_list.pop(idx)
				con_sub_list.insert( idx, bk )
				# print "Replacing at index " + str(idx)
				return
			# print margin + "Set sub_bk=" + Tag + " url=" + uri

			idx = idx + 1

		# print "Adding " + title + " to " + str(idx)
		bk["index"] = idx
		con_sub_list.append( bk )

	def JsonSet(self,title,url):
		# print "JsonSet " + title
		con_list = self.ReallyLoad()

		# Theoretically we should split the title based on a delimiter.

		# con_list[ title ] = bk
		con_sub_list = con_list['children']
		# print "Setting to " + title + " => " + url
		# print "con_sub_list=" + str(con_sub_list)
		# con_sub_list[ title ] = bk

		found = False
		for tmpbk in con_sub_list:
			if tmpbk["title"] == title:
				# Maybe we should also update the dates.
				tmpbk["uri"] = url
				found = True
				break

		if found == False:
			newbk = {
				"index":len(con_sub_list) + 1,
				"title":title,
				"id":19,
				"parent":2,
				"dateAdded":1208413037000000,
				"lastModified":1183706678000000,
				"type":"text/x-moz-place",
				"uri":url,
				"charset":"ISO-8859-1"}
			con_sub_list.append( newbk )

		# print "con_sub_list=" + str(con_sub_list)




# ON EN EST LA
		# print "htbin/internals/gui_bookmark_store.py create titi toto.org"




		# self.JsonSetAux(con_list,title,bk,"    ")
		self.SaveJson(con_list)

#	def JsonToJavascript(self,con_list,title,margin):
#Pas fini mais completemtn dommage alors que cette strcture est ce qu'il nous faut.
#		con_sub_list = con_list['children']
#		for sub_bk in con_sub_list:
#			try:
#				uri = sub_bk['uri']
#			except KeyError:
#				uri = ''
#			Tag = sub_bk['title']
#			# print margin + "sub_bk=" + Tag + " url=" + uri
#			if sub_bk.has_key('children'):
#				bookmarks = sub_bk['children']
#				if bookmarks:
#					self.JsonGetToJavascript(sub_bk,title,margin + "    ")
#			else:
#				if Tag == title:
#					return Bookmark.fromArray( sub_bk )
#		return ""

	# Also, we need to be able to list bookmarks per script,
	# so we can reedit them, because each script has the possiblity
	# to reedit cgis parameters using it.
	def NamesList(self):
		# con_list = self.ReallyLoad()
		# return con_list
		clean_json = self.LoadJson()
		return clean_json
		# return convert(con_list)
		# return clean_json
		# return PrintAsJavascript(con_list)
		# print JsonToJavascript(self,con_list)



# If it is used as a CGI program, it prints a page with all
# the available links in a javascript array.
# An array of arrays: Each sub-array contains the CGI parameters
# of each URL, plus the script.
# This variable is used to build a menu of the dynamic urls,
# but for a given script only. This is called by the script itself,
# which can then be used to calculate or to edit the parameters of an Urls.
# There are not too many scripts possible:
# - Merge.
# - projection with a SPARQL query (Single predicate or complex expression ?).
# The URL does NOT contain visualisation parameters.

def main():
	bms = BookmarkStore()
	print
	bkd = bms.JsonGet( "Nyman online accounts" )
	print
	print "Now we delete"
	bms.JsonDel( "Nyman online accounts" )

# For testing as a command line program.
if __name__ == '__main__':
	if len(sys.argv) == 1:
    		main()
		exit(0)

	action = sys.argv[1]
	bms = BookmarkStore()
	# htbin/internals/gui_bookmark_store.py create toto tutu
    	if action == "create":
		if len(sys.argv) != 4:
			print "Args should be: create <title> url"
			exit(1)
		bk = bms.JsonSet( sys.argv[2], sys.argv[3] )

		bk2 = bms.JsonGet( sys.argv[2] )
		bk2.Affiche()

    	elif action == "delete":
		if len(sys.argv) != 3:
			print "Args should be: delete <title>"
			exit(1)
		bms.JsonDel( sys.argv[2] )
	# htbin/internals/gui_bookmark_store.py show "Nyman online accounts"
    	elif action == "show":
		if len(sys.argv) != 3:
			print "Args should be: show <title>"
			exit(1)
		bk = bms.JsonGet( sys.argv[2] )

		try:
			bk.Affiche()
		except AttributeError:
			print "UndefinedTitle"
	else:
		print "Argv=" + action + " inconnu"
		exit(1)



