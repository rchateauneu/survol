
# https://pypi.python.org/pypi/barf/0.4.0

# This is a very simple example which shows how to open a binary file
# and print each instruction with its translation to the intermediate language (*REIL*).

import os
import sys
from barf import BARF

# https://pypi.python.org/pypi/barf/0.4.0
# It works but generates very small DOT files.
# We would like customize them, generate something else.

# Print assembly instruction.
#for addr, asm_instr, reil_instrs in barf.translate():
#	print("0x{addr:08x} {instr}".format(addr=addr, instr=asm_instr))

# Print REIL translation.
#for reil_instr in reil_instrs:
#	print("{indent:11s} {instr}".format(indent="", instr=reil_instr))

# z3 must be installed and in the path.as The command "where" must be accessible.
# Onn Windows, it is enough to copy which.exe to where.exe
# https://github.com/Z3Prover/z3

def TstBarf(file_path):
	barf = BARF(file_path)

	# Recover CFG.

	sys.stdout.write("dir=%s\n"%str(dir(barf)))
	cfg = barf.recover_cfg()
	basna = os.path.basename(file_path)

	# Save CFG to a .dot file.
	cfg.save(basna)


for file_path in [
	r"C:\Program Files (x86)\Git\bin\libaprutil-0-0.dll",
	r"C:\Program Files (x86)\Hewlett-Packard\Energy Star\ClearSysReg.exe",
	r"C:\Program Files (x86)\Hewlett-Packard\Energy Star\Estar.dll",
	r"C:\Program Files (x86)\Hewlett-Packard\Energy Star\msvcp100.dll",
]:
	TstBarf(file_path)
