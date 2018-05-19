import sys
# import importlib
import pandas as pd
import numpy
from sklearn.svm import SVC



class BufferAnalyzer:
	def __init__(self):
		# Load the CSV file.
		self.m_df = pd.read_csv('buffer_classes.csv',sep='\t')
		# df.head()

	# Returns None if it cannot find a match.
	# The CSV file associates a module name to each sample.
	def GetBufferClass(self,aBuffer):
		return None

	def ProcessBufferByClass(self,aBuffer):
		raise Exception("Not implemented now")

		# This module returns extra information from the buffer, as a dictionary.
		# This dict can be transformed to XML format.
		# These modules might return:
		# - Other detected objects such as SQL tables, in CIM format.
		# - Case ids for process mining: Basically data unique ids detected from a SQL query, a JSON document etc...

		# This should contain new CIM_like objects,
		# and also application-level case ids.

		modNam = self.GetBufferClass(aBuffer)
		importlib.importmodule( modNam )

G_BufferAnalyzer = BufferAnalyzer()

class BufferAccumulator:
	def __init__(self):
		self.m_currentBuffer = None
		self.m_informations_classes = None

	@staticmethod
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

	# When the current buffer has been reassembled.
	# This ensures that as few information as possible is stored.
	def AnalyseCompleteBuffer(self,aBuffer):
		bufClass = G_BufferAnalyzer.GetBufferClass(aBuffer)
		if bufClass:
			# Maybe we have several different identifications.
			try:
				self.m_informations_classes[bufClass] += 1
			except AttributeError:
				self.m_informations_classes = { bufClass : 1 }

	def GetContentClass(self):
		maxCla = None
		if self.m_informations_classes:
			maxNum = 0
			for cla,num in self.m_informations_classes:
				if maxNum < num:
					maxNum = num
					maxCla = cla
		return maxCla


	def AppendIOBuffer(self,aBuffer,szBuffer = 0):
		decodedBuffer = BufferAccumulator.DecodeOctalEscapeSequence(aBuffer)

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
			( ( szBuffer % 0x100 == 0 ) and ( szBuffer <= 0x1000) ) \
		or ( ( szBuffer % 0x1000 == 0 ) and ( szBuffer <= 0x10000) ) \
		or ( ( szBuffer % 0x10000 == 0 ) and ( szBuffer <= 0x100000) ) \
		or ( ( szBuffer % 0x100000 == 0 )  )

		if isSegment and (szBuffer == len(decodedBuffer)):
			if self.m_currentBuffer:
				self.m_currentBuffer += decodedBuffer
			else:
				self.m_currentBuffer = decodedBuffer
		else:
			if self.m_currentBuffer:
				self.AnalyseCompleteBuffer(self.m_currentBuffer)
				self.m_currentBuffer = None
			self.AnalyseCompleteBuffer(decodedBuffer)

def TestAnalysis():
	acc = BufferAccumulator()

	tstdat = [
		("qsldjhfqlksjdhflqjshd",None),
	]


	for tstPair in tstdat:
		acc.AppendIOBuffer(tstPair[0])
		aCla = acc.GetContentClass()
		sys.stdout.write("%20s %20s\n"%(aCla,tstPair[1]))

if __name__ == '__main__':
    TestAnalysis()