
# https://pypi.python.org/pypi/barf/0.4.0

# This is a very simple example which shows how to open a binary file
# and print each instruction with its translation to the intermediate language (*REIL*).

#```python
#from barf import BARF

# Open binary file.
#barf = BARF("examples/bin/x86/branch1")

# Print assembly instruction.
#for addr, asm_instr, reil_instrs in barf.translate():
#	print("0x{addr:08x} {instr}".format(addr=addr, instr=asm_instr))

# Print REIL translation.
#for reil_instr in reil_instrs:
#	print("{indent:11s} {instr}".format(indent="", instr=reil_instr))

# We can also recover the CFG and save it to a ``.dot`` file.

# Recover CFG.
# cfg = barf.recover_cfg()

# Save CFG to a .dot file.
# cfg.save("branch1_cfg")
