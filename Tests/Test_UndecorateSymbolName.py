import ctypes.wintypes

# If this does not work, it returns the input string.
def UndecorateSymbol(strSym):
	def UndecorateRaw(strSym):
		undname = ctypes.windll.dbghelp.UnDecorateSymbolName
		undname.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint]

		sizBuf = 50
		while True:
			ptrBuf = ctypes.create_string_buffer("Hello", sizBuf)
			sizActual = undname(strSym,ptrBuf,sizBuf,0)
			if sizActual < sizBuf - 2:
				return ptrBuf
			sizBuf *= 2

	strRaw = UndecorateRaw(strSym).value
	
	strRaw = strRaw.replace("__thiscall ","")
	
	for subStr in [ "private: ", "public: ", "protected: "]:
		if strRaw.startswith(subStr):
			strRaw = strRaw[ len(subStr): ]
			break
	
	return strRaw
	

			
tsts = [
	"??$_Getvals@_W@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@std@@@std@@IAEX_WABV_Locinfo@1@@Z",
	"??$_Getvals@_W@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@std@@@std@@IAEX_WABV_Locinfo@1@@Z",
	"??$_Getvals@_W@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@std@@@std@@IAEX_WABV_Locinfo@1@@Z",
	"??0?$_Yarn@D@std@@QAE@ABV01@@Z",
	"??0?$_Yarn@D@std@@QAE@PBD@Z",
	"??0?$_Yarn@D@std@@QAE@XZ",
	"??0?$_Yarn@_W@std@@QAE@XZ",
	"??0?$basic_ios@DU?$char_traits@D@std@@@std@@IAE@XZ",
	"??0?$basic_ios@DU?$char_traits@D@std@@@std@@QAE@PAV?$basic_streambuf@DU?$char_traits@D@std@@@1@@Z",
	"??0?$basic_ios@GU?$char_traits@G@std@@@std@@IAE@XZ",
	"??0?$basic_ios@GU?$char_traits@G@std@@@std@@QAE@PAV?$basic_streambuf@GU?$char_traits@G@std@@@1@@Z",
	"??0?$basic_ios@_WU?$char_traits@_W@std@@@std@@IAE@XZ",
	"??0?$basic_ios@_WU?$char_traits@_W@std@@@std@@QAE@PAV?$basic_streambuf@_WU?$char_traits@_W@std@@@1@@Z",
	"??0?$basic_iostream@DU?$char_traits@D@std@@@std@@IAE@$$QAV01@@Z",
	"??0?$basic_iostream@DU?$char_traits@D@std@@@std@@QAE@PAV?$basic_streambuf@DU?$char_traits@D@std@@@1@@Z",
	"??0?$basic_iostream@GU?$char_traits@G@std@@@std@@IAE@$$QAV01@@Z",
	"??0?$basic_iostream@GU?$char_traits@G@std@@@std@@QAE@PAV?$basic_streambuf@GU?$char_traits@G@std@@@1@@Z",
	"??0?$basic_iostream@_WU?$char_traits@_W@std@@@std@@IAE@$$QAV01@@Z",
	]

	
for tst in tsts[:]:
	sym = UndecorateSymbol(tst)
	print( sym )
	print("")
