import setuptools  # important
from distutils.core import setup
from Cython.Build import cythonize
import os
import sys
from shutil import copyfile

survol_base_dir = os.path.join(os.path.dirname(__file__), "..", "..", "survol")

# This is experimental for the moment.
# Check that some files can be cythonized, then run pytest.

def build_only_one_dir():
    src_files = []

    basenames_list = [
        "linux_api_definitions",
        "win32_api_definitions",
        #"cim_objects_definitions",
        # Import problem with Python 3
        ## "naming_conventions",

        # Unexplained bug yet (In summarization of function calls).
        # "dockit",
        "dockit_aggregate_clusterize",
    ]

    if sys.version_info >= (3,5):
        # Not this one because it uses __file__which is not usable by extensions due to this Python bug:
        # https://bugs.python.org/issue13429

        pass
        # Import problem with Python 3
        ## basenames_list.append("daemon_factory")

    for one_basename in basenames_list:
        one_filename = one_basename + ".py"
        one_path_name = os.path.join(survol_base_dir, "scripts", one_filename)
        src_files.append(one_path_name)

    language_level = "2" if sys.version_info < (3,) else "3"

    cython_ext_modules = cythonize(src_files, build_dir="build",
               compiler_directives={'language_level' : language_level})

    # With "force", the C code is regenerated each time. Otherwise, setup does not detect an input Python file change.
    setup(ext_modules=cython_ext_modules, script_args=['build'],
          options={
              'build': {'build_lib': '.', 'force': 1},
          })

    generated_base_dir = os.path.join(os.path.dirname(__file__), "survol")
    for one_basename in basenames_list:
        one_filename = one_basename + ".pyd"
        one_generated_path_name = os.path.join(generated_base_dir, "scripts", one_filename)
        one_destination_path_name = os.path.join(survol_base_dir, "scripts", one_filename)
        copyfile(one_generated_path_name, one_destination_path_name)

# Output files are created in ...\Experimental\tests_cython\survol\scripts

build_only_one_dir()


# In a typical Python installation, the ExtensionFileLoader class has precedence over the SourceFileLoader
# that is used for .py files. It's the ExtensionFileLoader which handles imports of .pyd files,
# and on a Windows machine you will find .pyd registered in importlib.machinery.EXTENSION_SUFFIXES
# (note: on Linux/macOS it will have .so in there instead).
#
# So in the case of name collision within same directory (which means a "tie" when looking through sys.path in order),
# the a.pyd file takes precedence over the a.py file. You may verify that when creating empty a.pyd and a.py files,
# the statement import a attempts the DLL load (and fails, of course).
#
# To see the precedence in the CPython sources, look here in importlib._bootstrap_external. _get_supported_file_loaders: