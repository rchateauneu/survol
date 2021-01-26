import setuptools  # important
from distutils.core import setup
from Cython.Build import cythonize
import os
import sys
from shutil import copyfile

survol_base_dir = os.path.join(os.path.dirname(__file__), "..", "..", "survol")

# This is experimental for the moment.
# Check that some files can be cythonized, then run pytest.

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

