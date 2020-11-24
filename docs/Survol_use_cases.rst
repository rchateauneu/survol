Use cases and scenarios:
========================
This document describes common use cases and usage scenarios of Survol, 
for solving common situations.

They focus on Linux only, to start with, with Primhill Computers demo machine
but the concepts are easily applicable to other platforms:

Oracle database:
================

The famous `TNSNAMES <filehttp://vps516494.ovh.net/Survol/survol/sources_types/Databases/oracle_tnsnames.py?xid=.PLAINTEXTONLY>`_
contain the list of accessible Oracle DBs.

See `Oracle Express <http://vps516494.ovh.net/Survol/survol/entity.py?xid=oracle/db.Db=XE>`_ scripts.

See `its schemas <http://vps516494.ovh.net/Survol/survol/sources_types/oracle/db/oracle_db_schemas.py?xid=oracle/db.Db%3DXE>`_

See `schema SYSTEM <http://vps516494.ovh.net/Survol/survol/entity.py?xid=oracle/schema.Db=XE,Schema=SYSTEM>`_

`List of tables of schema SYSTEM <http://vps516494.ovh.net/Survol/survol/sources_types/oracle/schema/oracle_schema_tables.py?xid=oracle/schema.Db%3DXE%2CSchema%3DSYSTEM>`_

Back to the top of XE database, now see `running Oracle sessions <http://vps516494.ovh.net/Survol/survol/sources_types/oracle/db/oracle_db_processes.py?xid=oracle/db.Db%3DXE>`_
Of course, the current process can be seen, running Python.

Which other machines are used by a running application ?
--------------------------------------------------------

Fetch the process

Sockets ?

Which external libraries are implied by an application ?
--------------------------------------------------------

Languages ?


Quelles librairies externes doivent etre installees.
----------------------------------------------------


Combien de langages.
Chercher certaines shared libs specifiques. (Comment)
Chercher des morceaux de scripts dans le code (Comment ?)
Chercher certaines chaines dans la memoire du process: Inevitable qui on lance un autre executable
(Comment a part chercher toutes les chaines ?)

 Ou bien: Lister les sous-processes et les trier par langage.

Quels schemas de bases de donnees ?
-----------------------------------

Quelles sockets avec numeros de ports douteux. Quels ports sont accedes ?

Dependencies of a running application:
--------------------------------------
This is the `entry point in SVG format <http://vps516494.ovh.net/Survol/survol/entity.py>`_.
All top -level scripts are here.

Get the `list of all processes <http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.PLAINTEXTONLY>`_ .

Now the `processes list in HTML format <http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.PLAINTEXTONLY&mode=html>`_
This is easier for a text search.

`All information about this process <http://rchateau-hp:8000/survol/entity.py?xid=CIM_Process.Handle=3888>`_

`Check the command line <http://rchateau-hp:8000/survol/sources_types/CIM_Process/process_command_line.py?xid=CIM_Process.Handle%3D3888>`_

`Fetch the executable <http://rchateau-hp:8000/survol/entity.py?xid=CIM_DataFile.Name=C%3A%2FProgram%20Files%2FMozilla%20Firefox%2Ffirefox.exe>`_
This is given with other informations about the process):

Fetch the `shared libraries of the process <http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/win_depends.py?xid=CIM_DataFile.Name%3DC%3A%2FProgram%20Files%2FMozilla%20Firefox%2Ffirefox.exe>`_

And `memory mapped segments <http://rchateau-hp:8000/survol/sources_types/CIM_Process/process_memmaps.py?xid=CIM_Process.Handle%3D3888>`_
(Which include dynamically loaded libraries):

Investigate interesting sockets on a machine:
---------------------------------------------
List of `TCP sockets <http://vps516494.ovh.net/Survol/survol/sources_types/Linux/tcp_sockets.py?xid=.PLAINTEXTONLY>`_

Click on a `socket <http://vps516494.ovh.net/Survol/survol/entity.py?xid=addr.Id=165.227.96.127:47892>`_ to see where it points to.

Some `information about this socket <http://vps516494.ovh.net/Survol/survol/sources_types/addr/socket_host.py?xid=addr.Id%3D165.227.96.127%3A47892>`_

