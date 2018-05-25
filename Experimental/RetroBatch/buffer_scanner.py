import sys
import re

import lib_sql

def DecodeOctalEscapeSequence(aBuffer):
	# An octal escape sequence consists of \ followed by one, two, or three octal digits.
	# The octal escape sequence ends when it either contains three octal digits already,
	# or the next character is not an octal digit.
	# For example, \11 is a single octal escape sequence denoting a byte with numerical value 9 (11 in octal),
	# rather than the escape sequence \1 followed by the digit 1.
	# However, \1111 is the octal escape sequence \111 followed by the digit 1.
	# In order to denote the byte with numerical value 1, followed by the digit 1,
	# one could use "\1""1", since C automatically concatenates adjacent string literals.
	# Note that some three-digit octal escape sequences may be too large to fit in a single byte;
	# this results in an implementation-defined value for the byte actually produced.
	# The escape sequence \0 is a commonly used octal escape sequence,
	# which denotes the null character, with value zero.
	# https://en.wikipedia.org/wiki/Escape_sequences_in_C

	# https://stackoverflow.com/questions/4020539/process-escape-sequences-in-a-string-in-python
	# bytes(myString, "utf-8").decode("unicode_escape") # python3
	# myString.decode('string_escape') # python2
	return aBuffer.decode('string_escape')

class BufferAccumulator:
	def __init__(self):
		self.m_currentBuffer = None

	def AnalyseCompleteBuffer(self,aBuffer):
		# Rechercher les requetes SQL.
		# Il faudrait un hint ??
		pass

	def GetStreamObjects(self):
		self.GetStreamObjects_SqlQueries()

	def GetStreamObjects_SqlQueries(self):
		dictRegexSQL = lib_sql.SqlRegularExpressions()

		# TODO: Unfortunately it scans several times the memory process.
		for rgxKey in dictRegexSQL:
			rgxSQL = dictRegexSQL[rgxKey]

			# https://docs.python.org/3/library/re.html
			# re.MULTILINE | re.ASCII | re.IGNORECASE
			matchedSqls = re.findall(self.m_currentBuffer,rgxSQL, re.IGNORECASE)
			#except Exception:
			#	exc = sys.exc_info()[1]
			#	lib_common.ErrorMessageHtml("Error:%s. Protection ?"%str(exc))

			setQrys = set()

			for sqlIdx in matchedSqls:
				sqlQry = matchedSqls[sqlIdx]
				setQrys.add(sqlQry)

			# This is just returning the list of detected SQL queries.
			# TODO: Extract the tables and views frm these queries.


#...


	def AppendIOBuffer(self,aFragment,szFragment = 0):
		decodedFragment = DecodeOctalEscapeSequence(aFragment)

		# Typical buffer size are multiple of 100x:
		#      256              100 #
		#      512              200 #
		#      768              300 #
		#    12288             3000 #
		#    24576             6000 #
		#    49152             c000 #
		#    65536            10000 #
		#   262144            40000 #

		isSegment = \
			( ( szFragment % 0x100 == 0 ) and ( szFragment <= 0x1000) ) \
		or ( ( szFragment % 0x1000 == 0 ) and ( szFragment <= 0x10000) ) \
		or ( ( szFragment % 0x10000 == 0 ) and ( szFragment <= 0x100000) ) \
		or ( ( szFragment % 0x100000 == 0 )  )

		if isSegment and (szFragment == len(decodedFragment)):
			if self.m_currentBuffer:
				self.m_currentBuffer += decodedFragment
			else:
				self.m_currentBuffer = decodedFragment
		else:
			if self.m_currentBuffer:
				self.AnalyseCompleteBuffer(self.m_currentBuffer)
				self.m_currentBuffer = None

			self.AnalyseCompleteBuffer(decodedFragment)

