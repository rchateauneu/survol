import sys
sys.path.insert(1,r'C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\htbin\revlib')

import sqlparse
import lib_sql

examplesQryGood = {
	"select aa from bb": ["BB"],
	"select b from a": ["A"],
	"select b*(b+1) from a": ["A"],
	"INSERT INTO table (nom_colonne_1, nom_colonne_2) VALUES ('valeur 1', 'valeur 2')" : ["TABLE"],
	"select cola,colc,colb from tab13 alias13,tab23 alias23":["TAB13","TAB23"],
	"select alias1.cola,colb from tab1 alias1, (select colb from tab2)":["TAB1","TAB2"],
	"select alias25.cola from (select colb from tab22) alias25":["TAB22"],
	"select tab22.cola from (select colb from tab22)":["TAB22"],
	"select cola,colc,colb from tab14,tab24":["TAB14","TAB24"],
	"select cola,colc,colb from tab14,tab24 alias24":["TAB14","TAB24"],
	"select cola from (select colb from tab22) alias2":["TAB22"],
	"select cola from tab11 alias1, (select colb from tab22) alias2":["TAB11","TAB22"],
	"select alias1.cola,alias2.colb from tab11 alias1, (select colb from tab22) alias2":["TAB11","TAB22"],
	"select cola from tab11, (select colb from tab22) alias2":["TAB11","TAB22"],
	"select cola,colc,colb from tab14,tab24 alias24":["TAB14","TAB24"],
	"""
	SELECT sess.status, sess.username, sess.schemaname, sql.sql_text,sql.sql_fulltext,proc.spid
	  FROM v$session sess,
		   v$sql     sql,
		   v$process proc
	 WHERE sql.sql_id(+) = sess.sql_id
	   AND sess.type     = 'USER'
	   and sess.paddr = proc.addr
	""":["V$PROCESS","V$SESSION","V$SQL"],
	"""
	SELECT distinct sess.sid, sess.username, sess.schemaname, proc.spid,pid,sess.osuser,sess.machine,sess.process,
	sess.port,proc.terminal,sess.program,proc.tracefile
	  FROM v$session sess,
		   v$process proc
	 WHERE sess.type     = 'USER'
	   and sess.paddr = proc.addr
	""":["V$PROCESS","V$SESSION"],
	"select tab1.cola,tab2.colb,tab3.colc from (select cola from tab1),(select colb from tab2),(select colc from tab3)":["TAB1","TAB2","TAB3"],
	"select cola,tab2.colb,tab3.colc from (select cola from tab1),(select colb from tab2),(select colc from tab3)":["TAB1","TAB2","TAB3"],
	"select ca,tab2.cb,tab3.cc from tab1,(select cb from tab2),(select cc from tab3)":["TAB1","TAB2","TAB3"],
	"select alias25.cola,alias15.colb from tab11 alias15,(select colb from tab22) alias25":["TAB11","TAB22"],
	"select cola,colb from (select colb from tab22) alias25,tab11 alias15":["TAB11","TAB22"],
	"select cola,colb from (select colb from tab22) alias25,tab11":["TAB11","TAB22"],
	"select cola,colb from (select colb from tab22),tab11 alias15":["TAB11","TAB22"],
	"select cola,colb from (select colb from tab22),tab11":["TAB11","TAB22"],
	"select cola,colb,colc from tab00,(select colb from tab22),tab11":["TAB00","TAB11","TAB22"],
	"select cola,colb,colc,cold from tab00,(select colb from tab22),tab11,(select colb from tab33)":["TAB00","TAB11","TAB22","TAB33"],
	"select cola,colb,colc,cold from (select cola from tab00),(select colb from tab22),tab11,(select colb from tab33)":["TAB00","TAB11","TAB22","TAB33"],
	"select cola,colb,colc,cold from tab00,tab22,tab11,(select colb from tab33)":["TAB00","TAB11","TAB22","TAB33"],
	"select b from a union (select c from d)": ["A","D"],
	"select b from a intersect (select c from d)": ["A","D"],
	"""
	select K.a,K.b from (select H.b from (select G.c from (select F.d from
	(select E.e from A, B, C, D, E), F), G), H), I, J, K order by 1,2;
	""" : ["A","B","C","D","E","F","G","H","I","J","K"],
}

examplesQryBad = {
	"select cola from tab14 where cold in (select c from tab140)":["TAB14","TAB140"],
}

def DisplayErrs(theDict):
	for sqlQry in theDict:
		print("QUERY="+sqlQry)
		resuXX = theDict[sqlQry]
		resVec = lib_sql.extract_sql_tables(sqlQry)
		resVec = [ s.upper() for s in resVec]
		vecUp = resVec
		vecUp.sort()
		if resuXX != vecUp:
			# print("QQQQQQQQQQQQQQQ="+sqlQry)
			print("Should be="+str(resuXX))
			# print("Actual is="+str(resVec))
			print("Sorted is="+str(vecUp))
			print("")
			print("")

print("\nGOOD")
DisplayErrs(examplesQryGood)
print("\nBAD")
DisplayErrs(examplesQryBad)

print("Fini")
