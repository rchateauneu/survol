import ctypes.wintypes


undname = ctypes.windll.dbghelp.UnDecorateSymbolName
undname.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint]

# If this does not work, it returns the input string.
def UndecorateSymbol(strSym):
	sizBuf = 200
	while True:
		ptrBuf = ctypes.create_string_buffer("", sizBuf)
		sizActual = undname(strSym,ptrBuf,sizBuf,0)
		if sizActual < sizBuf - 2:
			strRaw = ptrBuf.value
			break
		sizBuf *= 2

	# Now, some cleanup of useless strings. This tries to keep only the semantic information.
	for subStr in [ "__thiscall ", "__cdecl", "class ","struct "," __ptr64"]:
		strRaw = strRaw.replace(subStr,"")

	for subStr in [ "private: ", "public: ", "protected: "]:
		if strRaw.startswith(subStr):
			strRaw = strRaw[ len(subStr): ]
			break

	return strRaw

