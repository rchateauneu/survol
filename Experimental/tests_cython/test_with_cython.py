import setuptools  # important
from distutils.core import setup
from Cython.Build import cythonize
import os
src_file = os.path.join(os.path.dirname(__file__), "..", "..", "survol", "scripts", "linux_api_definitions.py")
setup(ext_modules=cythonize(src_file, build_dir="build"),
                                           script_args=['build'],
                                           options={'build':{'build_lib':'.'}})



# Result on Windows:
# C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\Experimental\tests_cython>python test_with_cython.py
# Compiling ..\..\survol\scripts\linux_api_definitions.py because it changed.
# [1/1] Cythonizing ..\..\survol\scripts\linux_api_definitions.py
# running build
# running build_ext
# building 'survol.scripts.linux_api_definitions' extension
# creating build
# creating build\temp.win-amd64-2.7
# creating build\temp.win-amd64-2.7\survol
# creating build\temp.win-amd64-2.7\survol\scripts
# C:\Users\rchateau\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe /c /nologo /Ox /MD /W3 /GS- /DNDEBUG -IC:\Python27\include -IC:\Python27\PC /Tcbuild\..\..\survol\scripts\linux_api_definitions.c /Fobuild\temp.win-amd64-2.7\Release\build\..\..\survol\scripts\linux_api_definitions.obj
# linux_api_definitions.c
# creating survol
# creating survol\scripts
# C:\Users\rchateau\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\link.exe /DLL /nologo /INCREMENTAL:NO /LIBPATH:C:\Python27\libs /LIBPATH:C:\Python27\PCbuild\amd64 /EXPORT:initlinux_api_definitions build\temp.win-amd64-2.7\Release\b
# uild\..\..\survol\scripts\linux_api_definitions.obj /OUT:.\survol\scripts\linux_api_definitions.pyd /IMPLIB:build\temp.win-amd64-2.7\Release\build\..\..\survol\scripts\linux_api_definitions.lib /MANIFESTFILE:build\temp.win-amd64-2.7\Release\build\..\..\survol\scripts\linux_api_definitions.pyd.manifestlinux_api_definitions.obj : warning LNK4197: export 'initlinux_api_definitions' specified multiple times; using first specification
#    Creating library build\temp.win-amd64-2.7\Release\build\..\..\survol\scripts\linux_api_definitions.lib and object build\temp.win-amd64-2.7\Release\build\..\..\survol\scripts\linux_api_definitions.exp