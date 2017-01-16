#!/usr/bin/python

"""
Windows users
"""

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

import lib_win32
import win32net
import win32netcon

from sources_types import Win32_UserAccount as survol_Win32_UserAccount

# Probably not necessary as it should not be able to import sources_types.Win32_UserAccount package.
Usable = lib_util.UsableWindows

def Main():
	cgiEnv = lib_common.CgiEnv()
	hostname = cgiEnv.GetId()

	nodeHost = lib_common.gUriGen.HostnameUri(hostname)

	grph = rdflib.Graph()

	# hostname = "Titi" for example
	lib_win32.WNetAddConnect(hostname)


	if lib_util.IsLocalAddress( hostname ):
		level = 2 # 1,2
	else:
		level = 2 # 1,2

	sys.stderr.write("hostname=%s level=%d\n" % (hostname,level))

	resumeHandle = 0

	while True:
		try:
			# Maintenant, comme tous les autres appels remote a Windows, ca retourne "access denied" vers Titi.
			# Comme s'il y avait avant une connection implicite.
			# Ou bien un Impersonate() ? On en a vire un qui ne marchait quand machine locale.
			# Peut-etre que le process du serveur en beneficiait tout le temps ?
			# Et meme WMI fonctionnait sans meme entrer le mot de passe.
			#
			# Connects a computer to or disconnects a computer from a shared resource, or displays information about computer connections.
			# The command also controls persistent net connections. Used without parameters, net use retrieves a list of network connections.
			# net use [{DeviceName | *}] [\\ComputerName\ShareName[\volume]] [{Password | *}]] [/user:[DomainName\]UserName]
			#  [/user:[DottedDomainName\]UserName] [/user: [UserName@DottedDomainName] [/savecred] [/smartcard] [{/delete | /persistent:{yes | no}}]
			# Ca marche si on fait ca avant:
			# net use \\Titi tXXXXXXa /user:Titi\rchateauneu@hotmail.com
			# https://mail.python.org/pipermail/python-win32/2003-April/000961.html
			lstUsers, total, resumeHandle = win32net.NetUserEnum(hostname,level,win32netcon.FILTER_NORMAL_ACCOUNT,resumeHandle)
		except:
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("NetUserEnum:"+str(exc))


		for usrElt in lstUsers:

			# {'comment': u'Built-in account for administering the computer/domain', 'workstations': u'', 'country_code': 0L, 'last_logon': 1426
			# 729970L, 'full_name': u'', 'parms': u'', 'code_page': 0L, 'priv': 2L, 'auth_flags': 0L, 'logon_server': u'\\\\*', 'home_dir': u'', '
			# usr_comment': u'', 'acct_expires': 4294967295L, 'bad_pw_count': 0L, 'logon_hours': '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff
			# \xff\xff\xff\xff\xff\xff\xff\xff\xff', 'password': None, 'units_per_week': 168L, 'last_logoff': 0L, 'name': u'Administrator', 'max_s
			# torage': 4294967295L, 'num_logons': 11L, 'password_age': 191184801L, 'flags': 66083L, 'script_path': u''},

			userName = usrElt['name']

			nodeUser = survol_Win32_UserAccount.MakeUri( userName, hostname )
			grph.add( ( nodeHost, pc.property_user, nodeUser ) )

			try:
				txtComment = usrElt['comment']
				grph.add( ( nodeUser, pc.property_information, rdflib.Literal(txtComment) ) )
			except KeyError:
				pass
		if resumeHandle == 0:
			break

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()



# >>> win32net.NetUserEnum(None,2)
# ([{'comment': u'Built-in account for administering the computer/domain', 'workstations': u'', 'country_code': 0L, 'last_logon': 1426
# 729970L, 'full_name': u'', 'parms': u'', 'code_page': 0L, 'priv': 2L, 'auth_flags': 0L, 'logon_server': u'\\\\*', 'home_dir': u'', '
# usr_comment': u'', 'acct_expires': 4294967295L, 'bad_pw_count': 0L, 'logon_hours': '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff
# \xff\xff\xff\xff\xff\xff\xff\xff\xff', 'password': None, 'units_per_week': 168L, 'last_logoff': 0L, 'name': u'Administrator', 'max_s
# torage': 4294967295L, 'num_logons': 11L, 'password_age': 191184801L, 'flags': 66083L, 'script_path': u''}, {'comment': u'Built-in ac
# count for guest access to the computer/domain', 'workstations': u'', 'country_code': 0L, 'last_logon': 1481437491L, 'full_name': u''
# , 'parms': u'', 'code_page': 0L, 'priv': 0L, 'auth_flags': 0L, 'logon_server': u'\\\\*', 'home_dir': u'', 'usr_comment': u'', 'acct_
# expires': 4294967295L, 'bad_pw_count': 0L, 'logon_hours': '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
# xff\xff\xff', 'password': None, 'units_per_week': 168L, 'last_logoff': 0L, 'name': u'Guest', 'max_storage': 4294967295L, 'num_logons
# ': 2L, 'password_age': 0L, 'flags': 66145L, 'script_path': u''}, {'comment': u'Built-in account for homegroup access to the computer
# ', 'workstations': u'', 'country_code': 0L, 'last_logon': 1436184697L, 'full_name': u'HomeGroupUser$', 'parms': u'', 'code_page': 0L
# , 'priv': 0L, 'auth_flags': 0L, 'logon_server': u'\\\\*', 'home_dir': u'', 'usr_comment': u'', 'acct_expires': 4294967295L, 'bad_pw_
# count': 0L, 'logon_hours': '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff', 'password': None,
#  'units_per_week': 168L, 'last_logoff': 0L, 'name': u'HomeGroupUser$', 'max_storage': 4294967295L, 'num_logons': 1L, 'password_age':
#  45311958L, 'flags': 66049L, 'script_path': u''}, {'comment': u'', 'workstations': u'', 'country_code': 0L, 'last_logon': 1480721751
# L, 'full_name': u'', 'parms': u'', 'code_page': 0L, 'priv': 2L, 'auth_flags': 0L, 'logon_server': u'\\\\*', 'home_dir': u'', 'usr_co
# mment': u'', 'acct_expires': 4294967295L, 'bad_pw_count': 0L, 'logon_hours': '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x
# ff\xff\xff\xff\xff\xff\xff\xff', 'password': None, 'units_per_week': 168L, 'last_logoff': 0L, 'name': u'rchateau', 'max_storage': 42
# 94967295L, 'num_logons': 15896L, 'password_age': 45311958L, 'flags': 66081L, 'script_path': u''}], 4, 0)
# >>> win32net.NetUserEnum("Titi",2)
# ([{'comment': u'Built-in account for administering the computer/domain', 'workstations': u'', 'country_code': 0L, 'last_logon': 1390
# 021250L, 'full_name': u'', 'parms': u'', 'code_page': 0L, 'priv': 2L, 'auth_flags': 0L, 'logon_server': u'\\\\*', 'home_dir': u'', '
# usr_comment': u'', 'acct_expires': 4294967295L, 'bad_pw_count': 0L, 'logon_hours': '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff
# \xff\xff\xff\xff\xff\xff\xff\xff\xff', 'password': None, 'units_per_week': 168L, 'last_logoff': 0L, 'name': u'Administrator', 'max_s
# torage': 4294967295L, 'num_logons': 14L, 'password_age': 104313843L, 'flags': 66051L, 'script_path': u''}, {'comment': u'Built-in ac
# count for guest access to the computer/domain', 'workstations': u'', 'country_code': 0L, 'last_logon': 0L, 'full_name': u'', 'parms'
# : u'', 'code_page': 0L, 'priv': 0L, 'auth_flags': 0L, 'logon_server': u'\\\\*', 'home_dir': u'', 'usr_comment': u'', 'acct_expires':
#  4294967295L, 'bad_pw_count': 0L, 'logon_hours': '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x
# ff', 'password': None, 'units_per_week': 168L, 'last_logoff': 0L, 'name': u'Guest', 'max_storage': 4294967295L, 'num_logons': 0L, 'p
# assword_age': 0L, 'flags': 66147L, 'script_path': u''}, {'comment': u'Built-in account for homegroup access to the computer', 'works
# tations': u'', 'country_code': 0L, 'last_logon': 0L, 'full_name': u'HomeGroupUser$', 'parms': u'', 'code_page': 0L, 'priv': 0L, 'aut
# h_flags': 0L, 'logon_server': u'\\\\*', 'home_dir': u'', 'usr_comment': u'', 'acct_expires': 4294967295L, 'bad_pw_count': 0L, 'logon
# _hours': '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff', 'password': None, 'units_per_week':
#  168L, 'last_logoff': 0L, 'name': u'HomeGroupUser$', 'max_storage': 4294967295L, 'num_logons': 0L, 'password_age': 63075285L, 'flags
# ': 66049L, 'script_path': u''}, {'comment': u'', 'workstations': u'', 'country_code': 0L, 'last_logon': 1481495518L, 'full_name': u'
# Remi Chateauneu', 'parms': u'', 'code_page': 0L, 'priv': 2L, 'auth_flags': 0L, 'logon_server': u'\\\\*', 'home_dir': u'', 'usr_comme
# nt': u'', 'acct_expires': 4294967295L, 'bad_pw_count': 0L, 'logon_hours': '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
# xff\xff\xff\xff\xff\xff\xff', 'password': None, 'units_per_week': 168L, 'last_logoff': 0L, 'name': u'rchat_000', 'max_storage': 4294
# 967295L, 'num_logons': 0L, 'password_age': 63075505L, 'flags': 66049L, 'script_path': u''}, {'comment': u'', 'workstations': u'', 'c
# ountry_code': 0L, 'last_logon': 1481495100L, 'full_name': u'vero', 'parms': u'', 'code_page': 0L, 'priv': 1L, 'auth_flags': 0L, 'log
# on_server': u'\\\\*', 'home_dir': u'', 'usr_comment': u'', 'acct_expires': 4294967295L, 'bad_pw_count': 0L, 'logon_hours': '\xff\xff
# \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff', 'password': None, 'units_per_week': 168L, 'last_logof
# f': 0L, 'name': u'vero', 'max_storage': 4294967295L, 'num_logons': 321L, 'password_age': 63074650L, 'flags': 66049L, 'script_path':
# u''}], 5, 0)
# >>> win32net.NetUserEnum("Titi",0)
# ([{'name': u'Administrator'}, {'name': u'Guest'}, {'name': u'HomeGroupUser$'}, {'name': u'rchat_000'}, {'name': u'vero'}], 5, 0)
# >>>

