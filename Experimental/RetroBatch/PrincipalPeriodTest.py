import sys

# Short text program to test the detection of periodic arrays.

# This is for strings only.
def PrincipalPeriodStr(aStr):
	ix = ( aStr + aStr ).find( aStr, 1, -1 )
	return ix

# This detects if an array os periodic without copying anything.
def PrincipalPeriod(aStr):
	# ix = ( aStr + aStr ).find( aStr, 1, -1 )
	# return ix
	lenStr = len(aStr)
	lenStr2 = lenStr - 1
	sys.stdout.write("aStr=%s lenStr2=%d\n"%(aStr,lenStr2))

	ixStr = 1
	while ixStr <= lenStr2:
		ixSubStr = 0
		while ixSubStr < lenStr:
			ixTotal = ixStr + ixSubStr
			if ixTotal >= lenStr:
				ixTotal -= lenStr

			# sys.stdout.write("ixTotal=%d ixSubStr=%d\n"%(ixTotal,ixSubStr))
			if aStr[ ixSubStr ] != aStr[ ixTotal ]:
				break
			ixSubStr += 1

		if ixSubStr == lenStr:
			return ixStr
		ixStr += 1
	return -1

def Tst(aStr):
	i1 = PrincipalPeriod(aStr)
	i2 = PrincipalPeriodStr(aStr)
	if i1 != i2:
		print("??:%s %d"%(aStr,i1))
		print("OK:%s %d"%(aStr,i2))
		print("")

Tst("aa")
Tst("ab")
Tst("abab")
Tst("abcabc")
Tst("abcxabc")
Tst("xabcabc")
Tst("abcabyc")
Tst("xxx")
Tst("xyzxyzxyzxyz")
Tst("123123123123k")

