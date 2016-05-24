import sys

# Find first index of delimiter if this is not enclosed.
def find_closing_delimiter(instr,idx,char_open,char_close):
	bracket_level = 0
	lenInstr = len(instr)
	while idx < lenInstr:
		ch = instr[idx]
		if ch == char_open:
			bracket_level += 1
		elif ch == char_close:
			bracket_level -= 1

		sys.stderr.write("ch=%s idx=%d bracket_level=%d\n" % ( ch, idx, bracket_level) )
		if bracket_level == 0:
			return idx
		idx += 1
	return -1 # Not found.


# top_level_split( "aa::bb<cc::dd>::ee","::","<",">")
# This splits a string based on a delimiter, if not enclosed in brackets or parenthesis.
def top_level_split(instr,delim,bracket_open,bracket_close):
	parts = []
	bracket_level = 0
	current = ""
	# sys.stdout.write("str=%s delim=%s\n" % ( instr, delim ) )
	# trick to remove special-case of trailing chars
	lenInstr = len(instr)
	idx = 0
	while idx < lenInstr:
		# sys.stdout.write("startswith=%d idx=%d cur=%s\n" % ( instr.startswith( delim, idx ), idx, current ))
		if instr.startswith( delim, idx ) and bracket_level == 0:
			if current:
				parts.append(current)
			current = ""
			idx += len(delim)
		else:
			ch = instr[idx]
			if ch in bracket_open:
				bracket_level += 1
			elif ch in bracket_close:
				bracket_level -= 1
			current += ch
			idx += 1
	if current:
		parts.append(current)
	if not parts:
		parts = [""]
	# sys.stdout.write("str=%s parts=%s\n" % ( instr, str(parts) ) )
	return parts

################################################################################


scalarTypes = set( [
	"bool",
	"short",
	"unsigned short",
	"int",
	"unsigned int",
	"long",
	"unsigned long",
	"long long",
	"unsigned long long",
	"float",
	"double", ]
	)

# unsigned short const*
# xercesc_3_1::ValueStore const*
# xercesc_3_1::RefVectorOf<xercesc_3_1::XMLAttr> const&
# bool
# xercesc_3_1::RefHash2KeysTableBucketElem<xercesc_3_1::ValueVectorOf<xercesc_3_1::SchemaElementDecl*> >**

def ExtractClassesFromType(lstCls, cls):
	if not cls:
		return
	while cls[-1] in "*&":
		cls = cls[:-1]

	if cls.endswith(" const"):
		cls = cls[:-6]

	# This is just for the most common cases because it cannot eliminate typedefs.
	if cls in scalarTypes:
		return

	lstCls.append( cls )

	# There might also be template parameters.
	ExtractTemplatedClassesFromToken( lstCls, cls )

# There might be several template parameters.
# XMLEnumerator<xercesc_3_1::FieldValueMap>
def ExtractTemplatedClassesFromToken(lstCls, cls):
	bracketFirst = cls.find("<")
	if bracketFirst <= 0:
		return None
	bracketLast = cls.rfind(">")
	strTmplArgs = cls[ bracketFirst + 1: bracketLast ]

	# Beware : Add other delimiters if template parameters contain "()"
	# such as function pointers.
	tmplArgs = top_level_split( strTmplArgs, ",", "<", ">" )
	for tmplArg in tmplArgs:
		ExtractClassesFromType( lstCls, tmplArg )

################################################################################

# void (* _set_se_translator(void (*)(unsigned int,struct _EXCEPTION_POINTERS * __ptr64)))(unsigned int,struct _EXCEPTION_POINTERS * __ptr64)
def FindArgumentsStart(symDemang):
	firstOpeningPar = symDemang.find("(")
	closingPar = find_closing_delimiter(symDemang, firstOpeningPar, "(", ")" )
	secondOpeningPar = symDemang.find("(",closingPar)
	if secondOpeningPar >= 0:
		return secondOpeningPar
	else:
		return firstOpeningPar

# This extracts the arguments from a demangled symbol.
def SymToArgs(symDemang):

	firstPar = FindArgumentsStart(symDemang)
	if firstPar < 0:
		# This is a singleton.
		fulNam = symDemang
		lstArgs = None # Different from zero arguments.
	else:
		fulNam = symDemang[:firstPar]
		# There might be ") const" at the end.

		#if symDemang.endswith(" const"):
		#	# TODO: We are sure that the last token is a class, not a namespace.
		#	endIdx = -7
		#else:
		#	endIdx = -1
		endIdx = symDemang.rfind(")")
		argsNoParenth = symDemang[firstPar+1:endIdx]
		if argsNoParenth == "":
			lstArgs = [] # Zero argument.
		else:
			# TODO: Arguments cannot be namespaces. Template parameters also.
			lstArgs = [ arg.strip() for arg in top_level_split(argsNoParenth,",","<",">") ]

	return ( fulNam, lstArgs )

