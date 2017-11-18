# http://timgolden.me.uk/pywin32-docs/html/win32/help/security_directories.html

import os
import sys
import win32net
import string
import time
import copy
import getopt

#the extension module
# import fileperm

All_perms={
    1:"ACCESS_READ",            #0x00000001
    2:"ACCESS_WRITE",           #0x00000002
    4:"ACCESS_CREATE",          #0x00000004
    8:"ACCESS_EXEC",            #0x00000008
    16:"ACCESS_DELETE",         #0x00000010
    32:"ACCESS_ATRIB [sic]",    #0x00000020
    64:"ACCESS_PERM",           #0x00000040
    32768:"ACCESS_GROUP",       #0x00008000
    65536:"DELETE",             #0x00010000
    131072:"READ_CONTROL",      #0x00020000
    262144:"WRITE_DAC",         #0x00040000
    524288:"WRITE_OWNER",       #0x00080000
    1048576:"SYNCHRONIZE",      #0x00100000
    16777216:"ACCESS_SYSTEM_SECURITY",#0x01000000
    33554432:"MAXIMUM_ALLOWED", #0x02000000
    268435456:"GENERIC_ALL",    #0x10000000
    536870912:"GENERIC_EXECUTE",#0x20000000
    1073741824:"GENERIC_WRITE", #0x40000000
    65535:"SPECIFIC_RIGHTS_ALL",#0x0000ffff
    983040:"STANDARD_RIGHTS_REQUIRED",#0x000f0000
    2031616:"STANDARD_RIGHTS_ALL",#0x001f0000
    }

Typical_perms={
    2032127L:"Full Control(All)",
    1179817L:"Read(RX)",
    1180086L:"Add",
    1180095L:"Add&Read",
    1245631L:"Change"
}


def get_mask(mask):
    a=2147483648L
    if Typical_perms.has_key(mask):
        return Typical_perms[mask]
    else:
        result=''
        while a>>1:
            a=a>>1
            masked=mask&a
            if masked:
                if All_perms.has_key(masked):
                    result=All_perms[masked]+':'+result
    return result


def is_group(sys_id):
    #get the server for the domain -- it has to be a primary dc
    group=0
    resume=0
    sys_id=string.strip(sys_id)
    if D_group.has_key(sys_id):
        group=1
    elif D_except.has_key(sys_id):
        group=0
    else:
        try:
            #info returns a dictionary of information
            info = win32net.NetGroupGetInfo(Server, sys_id, 0)
            group=1
        except:
            try:
                win32net.NetLocalGroupGetMembers(Server, sys_id, 0,resume,4096)
                group=1
            except:
                pass
    return group


# def get_perm_base(file):
#     all_perms=fileperm.get_perms(file)
#     for (domain_id,mask) in all_perms.items():
#         (domain,sys_id)=string.split(domain_id,'\\',1)
#         mask_name=get_mask(mask)
#         Results.append(file+','+sys_id+','+mask_name)
#
# def get_perm(file):
#     perm_list=[]
#     perm_list.append(file)
#     all_perms=fileperm.get_perms(file)
#     for (domain_id,mask) in all_perms.items():
#         (domain,sys_id)=string.split(domain_id,'\\',1)
#         print domain,sys_id
#         sys_id=str(sys_id)
#         mask_name=get_mask(mask)
#         if len(sys_id)<7:
#             perm_list.append(sys_id+'\t\t\t'+mask_name)
#         elif len(sys_id)>14:
#             perm_list.append(sys_id+'\t'+mask_name)
#         else:
#             perm_list.append(sys_id+'\t\t'+mask_name)
#     return perm_list
# def get_perms(arg, d, files):
#     a=2147483648L #1L<<31L
#     print 'Now at ',d
#     for i in files:
#         file=d+'\\'+i
#         if opts['-d']:
#             if not os.path.isdir(file): # skip non-directories
#                 continue
#         all_perms=fileperm.get_perms(file)
#         for (domain_id,mask) in all_perms.items():
#             if string.find(domain_id,'\\')!=-1:
#                 (domain,sys_id)=string.split(domain_id,'\\',1)
#             else:
#                 sys_id=domain_id
#             mask_name=get_mask(mask)
#             Results.append(file+','+sys_id+','+mask_name)
#     Results.sort()
#     return Results
######################################################################################################
#h - help
#r - recursive
#o - output file
#d - directories only

domain='HOMEGROUP'

Server=str(win32net.NetGetDCName("",domain))
print '************************ Using domain ',domain

only_dir=0
D_group={}
D_except={}
if len(sys.argv)==1:
    print sys.argv[0]," file or directory"
    print "-r for recursive mode \n-o for output file (default screen) \n-d for directories only"
    print 'Example:',sys.argv[0],'-o a.txt -r c:\\junk  \n ----goes down dir tree in c:\\junk and saves in a.txt'
    sys.exit(0)
else:
    try:
        optlist, args = getopt.getopt(sys.argv[1:], 'dho:r')
    except getopt.error:
       print "invalid option.  available options are: -d -h -r -o "
       print "-r for recursive mode \n-o for output file (default screen) \n-d for directories only"

       sys.exit(0)

    opts = {'-d':0,'-h':0,'-o':0,'-r':0}
    for key, value in optlist:
        opts[key]=1
        if key == '-o':
            opts[key]=value
    init=time.clock()


    Results=[]
    if opts['-r']:
        if os.path.isdir(args[0]):
            print 'walking thru',args[0]
            # get_perm_base(args[0])
            # os.path.walk(args[0],get_perms,opts['-d'])
        else:
            print 'Directory',args[0],'does not exist'
            sys.exit(0)
    else:
        if os.path.exists(args[0]):
            # Results=get_perm(args[0])
            pass
        else:
            print 'Directory or file',args[0],'does not exist'
            sys.exit(0)

    #now print out the results
    if opts['-o']:
        #send to a file
        print 'Storing results in',opts['-o']
        f=open(opts['-o'],'w')
        for i in Results:
            f.write(i)
            f.write('\n')
    else:
        for i in Results:
            print i
        end = time.clock()-init
