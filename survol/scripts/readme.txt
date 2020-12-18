Scripts in this directory are for example HTTP servers.
They do not depend on the Python library, their PYTHONPATH
does not need to point to the survol directory.
For example, they do not need files in survol/lib_*.py.
The reason is to be able to run dockit.py just by copying a couple of files for the directory scripts/.

They can be imported for general Survol sources, for example files in survol/lib_*.py
or the CGI scripts in survol/sources_types.