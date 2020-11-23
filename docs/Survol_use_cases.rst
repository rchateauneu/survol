Use cases and scenarios:
========================
This document describes common use cases and usage scenarios of Survol, 
for solving common situations.

They focus on Linux only, to start with, with Primhill Computers demo machine
but the concepts are easily applicable to other platforms:

Dependencies of a running application:
--------------------------------------
This is the `entry point in SVG format <http://vps516494.ovh.net/Survol/survol/entity.py>`_.
All top -level scripts are here.

Get the `list of all processes <http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.PLAINTEXTONLY>`_ .

Now the `processes list in HTML format <http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.PLAINTEXTONLY&mode=html>`_
This is easier for a search.

http://rchateau-hp:8000/survol/sources_types/enumerate_CIM_Process.py?xid=.PLAINTEXTONLY&mode=html

All information about this process:
http://rchateau-hp:8000/survol/entity.py?xid=CIM_Process.Handle=3888

Check the command line:
http://rchateau-hp:8000/survol/sources_types/CIM_Process/process_command_line.py?xid=CIM_Process.Handle%3D3888

Fetch the executable (This is given with other informatiosn about the process)::
http://rchateau-hp:8000/survol/entity.py?xid=CIM_DataFile.Name=C%3A%2FProgram%20Files%2FMozilla%20Firefox%2Ffirefox.exe

Fetch the shared libraries of the process:
http://rchateau-hp:8000/survol/sources_types/CIM_DataFile/win_depends.py?xid=CIM_DataFile.Name%3DC%3A%2FProgram%20Files%2FMozilla%20Firefox%2Ffirefox.exe

And memory mapped segments (Which include dynamically loaded libraries):
http://rchateau-hp:8000/survol/sources_types/CIM_Process/process_memmaps.py?xid=CIM_Process.Handle%3D3888

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
