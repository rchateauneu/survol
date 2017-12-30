# import capstone

from capstone import *
from capstone.arm import *

def TestHeavy():
	CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	for i in md.disasm(CODE, 0x1000):
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

def TestLight():
	CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"

	md = Cs(CS_ARCH_X86, CS_MODE_64)
	for (address, size, mnemonic, op_str) in md.disasm_lite(CODE, 0x1000):
		print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))

def TestThree():
	CODE = b"\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
	md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
	md.detail = True

	for i in md.disasm(CODE, 0x1000):
		if i.id in (ARM_INS_BL, ARM_INS_CMP):
			print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

		if len(i.regs_read) > 0:
			print("\tImplicit registers read: "),
			for r in i.regs_read:
				print("%s " %i.reg_name(r)),
			print

		if len(i.groups) > 0:
			print("\tThis instruction belongs to groups:"),
			for g in i.groups:
				print("%u" %g),
			print

TestHeavy()
TestLight()
TestThree()

rr = raw_input("Press return:")

#name = input("What's your name? ")
#print("Nice to meet you " + name + "!")
#age = input("Your age? ")
#print("So, you are already " + str(age) + " years old, " + name + "!")
