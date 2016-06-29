import sys
import win32api
import win32net
import win32netcon
import win32security
import getopt
import traceback
  
verbose_level = 1
  
server = None # Run on local machine.
  
def verbose(msg):
    if verbose_level:
        print(msg)

################################################################################
  
import odbc


def show_odbc_sources():
	source = odbc.SQLDataSources(odbc.SQL_FETCH_FIRST)
	print("Source=" + str(source) )
	while source:
		dsn, driver = source
		source = odbc.SQLDataSources(odbc.SQL_FETCH_NEXT)
		print("Source=" + str(source) )

################################################################################


def UserEnum():
    "Enumerates all the local users"
    resume = 0
    nuser = 0
    while 1:
        data, total, resume = win32net.NetUserEnum(server, 3, win32netcon.FILTER_NORMAL_ACCOUNT, resume)
        verbose("Call to NetUserEnum obtained %d entries of %d total" % (len(data), total))
        for user in data:
            verbose("Found user %s" % user['name'])
            nuser = nuser + 1
        if not resume:
            break
    print("Enumerated all the local users")

def GroupEnum():
    "Enumerates all the domain groups"
    nmembers = 0
    resume = 0
    while 1:
        data, total, resume = win32net.NetGroupEnum(server, 1, resume)
#               print "Call to NetGroupEnum obtained %d entries of %d total" % (len(data), total)
        for group in data:
            verbose("Found group %(name)s:%(comment)s " % group)
            memberresume = 0
            while 1:
                memberdata, total, memberresume = win32net.NetGroupGetUsers(server, group['name'], 0, resume)
                for member in memberdata:
                    verbose(" Member %(name)s" % member)
                    nmembers = nmembers + 1
                if memberresume==0:
                    break
        if not resume:
            break
 
def ServerEnum():
    "Enumerates all servers on the network"
    resume = 0
    while 1:
        data, total, resume = win32net.NetServerEnum(server, 100, win32netcon.SV_TYPE_ALL, None, resume)
        for s in data:
            verbose("Server %s" % s['name'])
            # Now loop over the shares.
            shareresume=0
            while 1:
                sharedata, total, shareresume = win32net.NetShareEnum(server, 2, shareresume)
                for share in sharedata:
                    verbose("    %(netname)s (%(path)s):%(remark)s - in use by %(current_uses)d users" % share)
                if not shareresume:
                    break
        if not resume:
            break
  
def GetInfo(userName=None):
    "Dumps level 3 information about the current user"
    if userName is None: userName=win32api.GetUserName()
    print( "Dumping level 3 information about user")
    info = win32net.NetUserGetInfo(server, userName, 3)
    for key, val in info.items():
        verbose("%s=%s" % (key,val))
  



show_odbc_sources()
print("")
UserEnum()
print("")
GroupEnum()
print("")
ServerEnum()
print("")
GetInfo()

print("Fini")