import ctypes.wintypes


undname = ctypes.windll.dbghelp.UnDecorateSymbolName
undname.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint]

# If this does not work, it returns the input string.
def UndecorateSymbol(strSym):
	sizBuf = 200
	while True:
		ptrBuf = ctypes.create_string_buffer(b"", sizBuf)
		sizActual = undname(strSym,ptrBuf,sizBuf,0)
		if sizActual < sizBuf - 2:
			strRaw = ptrBuf.value
			break
		sizBuf *= 2

	# Now, some cleanup of useless strings. This tries to keep only the semantic information.
	for subStr in [ b"__thiscall ", b"__cdecl", b"class ",b"struct ",b" __ptr64"]:
		strRaw = strRaw.replace(subStr,b"")

	for subStr in [ b"private: ", b"public: ", b"protected: "]:
		if strRaw.startswith(subStr):
			strRaw = strRaw[ len(subStr): ]
			break

	return strRaw

