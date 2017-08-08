import sys
import os
import re


tst_data = {
	"xxx/entity.py?xid=typ1:id1",
	"xxx/entity.py?xid=host2@typ2:id2"
	}

for dat in tst_data:
	mtch = re.match( "^.*/entity.py\?xid=([^@]*@)?([a-z0-9A-Z]*):(.*)$", dat )
	if mtch:
		print("l=%d" % len(mtch.groups()))
		print("resu="+str(mtch.groups()))
		# print("typ=%s id=%s host=%s" % ( mtch.group(1), mtch.group(2), mtch.group(3) ) )
	else:
		print("Fail")

print("Fini")