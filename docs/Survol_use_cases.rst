Use cases and scenarios:
========================
This document describes common use cases and usage scenarios of Survol, 
for solving common situations.

They focus on Linux only, to start with, running on Primhill Computers demo machine
but the concepts are easily applicable to other platforms.

TODO:
=====

Dockerfile:
-----------
The command dockit is able in a certain extent to cerate a Dockerfile reproducing the execution of a command.

Makefile:
---------

Makefiles tend to grow with time, as their target application gets more and more new components.
The dependencies can be very difficult to understand.
These dependencies can be hidden: Some tools might implicitly create output files.

The command dockit analyse a process and rebuilds a makefile.


Which external libraries are implied by an application ?
--------------------------------------------------------

Languages ?


MySql
-----

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

Dockerfile:
-----------



DONE
====

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


Oracle database:
----------------

The famous `TNSNAMES <filehttp://vps516494.ovh.net/Survol/survol/sources_types/Databases/oracle_tnsnames.py?xid=.PLAINTEXTONLY>`_
contain the list of accessible Oracle DBs.

See `Oracle Express <http://vps516494.ovh.net/Survol/survol/entity.py?xid=oracle/db.Db=XE>`_ scripts.

See `its schemas <http://vps516494.ovh.net/Survol/survol/sources_types/oracle/db/oracle_db_schemas.py?xid=oracle/db.Db%3DXE>`_

See `schema SYSTEM <http://vps516494.ovh.net/Survol/survol/entity.py?xid=oracle/schema.Db=XE,Schema=SYSTEM>`_

`List of tables of schema SYSTEM <http://vps516494.ovh.net/Survol/survol/sources_types/oracle/schema/oracle_schema_tables.py?xid=oracle/schema.Db%3DXE%2CSchema%3DSYSTEM>`_

Back to the top of XE database, now see `running Oracle sessions <http://vps516494.ovh.net/Survol/survol/sources_types/oracle/db/oracle_db_processes.py?xid=oracle/db.Db%3DXE>`_
Of course, the current process can be seen, running Python.

External machines:
------------------

Get `sockets with netstat <http://vps516494.ovh.net/Survol/survol/sources_types/Linux/tcp_sockets.py?xid=.PLAINTEXTONLY>`_

Click `socket icon <http://vps516494.ovh.net/Survol/survol/entity.py?xid=addr.Id=90.254.241.42:52713>`_
to see its owner and other information.

Check what a user is doing:
---------------------------

See `list of users <http://vps516494.ovh.net/Survol/survol/sources_types/Linux/etc_passwd.py?xid=.PLAINTEXTONLY>`_

See `user apache <http://vps516494.ovh.net/Survol/survol/entity.py?xid=LMI_Account.Name=apache,Domain=vps516494.ovh.net>`_.
Due to security reason, this is the only one we can easily investigate (Because it runs
the HTTP server and is therefore accessible).

Which process is run by `apache <http://vps516494.ovh.net/Survol/survol/sources_types/LMI_Account/user_processes.py?xid=LMI_Account.Name%3Dapache%2CDomain%3Dvps516494.ovh.net>`_ ?

It runs httpd servers and also a Python process for the current CGI script.

See the `parent process <http://vps516494.ovh.net/Survol/survol/entity.py?xid=CIM_Process.Handle=302>`_
(The one at the center).

Which other machines are used by a running application ?
--------------------------------------------------------

Note that this demo machine is higly secured and does not allow much detection.
Still, various scripts are usable.

* `Detect other machines on the LAN with ARP <http://vps516494.ovh.net/Survol/survol/sources_types/neighborhood/cgi_arp_async.py?xid=.PLAINTEXTONLY>`_
* `ARP variant, but faster <http://vps516494.ovh.net/Survol/survol/sources_types/Linux/cgi_arp_linux.py?xid=.PLAINTEXTONLY>`_
* `Neighboring WBEM agents <http://vps516494.ovh.net/Survol/survol/sources_types/neighborhood/wbem_neighborhood.py?xid=.PLAINTEXTONLY>`_ : In this demo, there are pre-registered, but it is possible to detect them with SLP. It is not necessary to install Survol on this distant machine if a WBEM agent is running on it, because Surol is able to query it.
* `NMAP <http://vps516494.ovh.net/Survol/survol/sources_types/nmap/nmap_run.py?xid=.PLAINTEXTONLY>`_ : NMAP allows many different scripts to explore a network. Only some features are used in Survol at the moment.

Once a machine is selected, other queries are possible.

`Take the current machine as an example <http://vps516494.ovh.net/Survol/survol/entity.py?xid=CIM_ComputerSystem.Name=vps516494.ovh.net>`_

`JAVA RMI can be used on a distant machine <http://vps516494.ovh.net/Survol/survol/sources_types/CIM_ComputerSystem/java/rmi_registry.py?xid=CIM_ComputerSystem.Name%3Dvps516494.ovh.net>`_. Here again, it is not needed to have a Survol agent running on a dstant machine if RMI is accessible, because Survol uses this protocol and translates the result into RDF representation.

`WBEM can also be used locally <http://vps516494.ovh.net/Survol/survol/sources_types/CIM_ComputerSystem/wbem_hostname_processes.py?xid=CIM_ComputerSystem.Name%3Dvps516494.ovh.net>`_ : If a WBEM serveur is installed on a machine, it can be queried. Especially, the information of its providers is available without extra development.

When on a Microsoft Windows machine, WMI offers the same features as WBEM on Linux.

