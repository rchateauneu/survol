import sys
import re
# import importlib
import csv
import pandas as pd
import warnings

# function for transforming documents into counts
from sklearn.feature_extraction.text import CountVectorizer
# function for encoding categories
from sklearn.preprocessing import LabelEncoder

from sklearn.naive_bayes import MultinomialNB

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.externals import joblib

if not sys.warnoptions:
	warnings.simplefilter("ignore")

# https://www.quantstart.com/articles/Supervised-Learning-for-Document-Classification-with-Scikit-Learn
# TODO: Not really appropriate.
def normalize_text(s):
	s = s.lower()

	# remove punctuation that is not word-internal (e.g., hyphens, apostrophes)
	s = re.sub('\s\W',' ',s)
	s = re.sub('\W\s',' ',s)

	# make sure we didn't introduce any double spaces
	s = re.sub('\s+',' ',s)

	return s

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

def OctalAndNormalize(aBuffer):
	return DecodeOctalEscapeSequence(normalize_text(aBuffer))


class BufferAnalyzer:
	def __init__(self,rebuild):
		self.m_csvNam = 'buffer_classes.csv'
		# Load the CSV file.
		# self.m_df = pd.read_csv(self.m_csvNam,delimiter='\t')

		self.m_rebuild = rebuild
		self.m_pklFil = 'buffer_analysis.pkl'

		if self.m_rebuild:
			self.BuildEngine()
		else:
			self.LoadEngine()

	def LoadEngine(self):
		self.m_classifier = joblib.load(self.m_pklFil)

	def BuildEngine(self):

		fdCsv = open(self.m_csvNam, "r")
		reader = csv.reader(fdCsv, delimiter=" ")

		# Two columns.
		rows = [ [ aLin[:1], ' '.join(aLin[1:]) ] for aLin in reader]
		print("Rows size:")
		print(len(rows))
		#print("Rows:")
		#print(rows)
		self.m_df = pd.DataFrame(rows)
		fdCsv.close()
		print("Head shape:")
		print(self.m_df.shape)
		#print("Head:")
		#print(self.m_df.head())

		# https://www.kaggle.com/kinguistics/classifying-news-headlines-with-scikit-learn

		print("Before normalize")
		# module buffer
		self.m_df[2] = [OctalAndNormalize(aBuffer) for aBuffer in self.m_df[1]]

		print("Head shape after normalization:")
		print(self.m_df.shape)

		print("Head after normalization:")
		print(self.m_df.head(30))

		# http://scikit-learn.org/stable/modules/feature_extraction.html
		# No need to override the tokenizer yet.
		# lowercase
		# token_pattern
		self.m_vectorizer = CountVectorizer(analyzer='word', ngram_range=(1, 3), decode_error='ignore', input='content')

		x = self.m_vectorizer.fit_transform(self.m_df[2])

		self.m_encoder = LabelEncoder()
		y = self.m_encoder.fit_transform(self.m_df[0])

		# split into train and test sets
		x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.1)

		self.m_classifier = MultinomialNB().fit(x_train, y_train)

		print("About to dump model to:%s"%self.m_pklFil)
		joblib.dump(self.m_classifier, self.m_pklFil)

		print("About to predict: shape=%s"% str(x_test.shape))
		#print("Predicting %d samples" % len(x_test) )
		y_pred = self.m_classifier.predict(x_test)
		print("After predict")

		# UndefinedMetricWarning: Precision and F-score are ill-defined and being set to 0.0 in labels with no predicted samples.

		print("Confusion matrix:")
		cm = confusion_matrix(y_test,y_pred)
		print(cm.shape)

		# print(str(type(cm)))
		# (109L, 109L)
		# <type 'numpy.ndarray'>

		ix = 0
		while ix < cm.shape[0]:
			iy = 0
			while iy < cm.shape[1]:
				sys.stdout.write("%4d" % cm[ix][iy])
				iy += 1
			ix += 1
			sys.stdout.write("\n")
		sys.stdout.write("\n")

		print("Classification report:")
		print(classification_report(y_test,y_pred))



	# Returns None if it cannot find a match.
	# The CSV file associates a module name to each sample.
	def GetBufferClass(self,aBuffer):
		bufClean = OctalAndNormalize(aBuffer)

		trf = self.m_vectorizer.transform([bufClean])

		aClas = self.m_classifier.predict(trf)

		anInv = self.m_encoder.inverse_transform(aClas)
		deco = anInv[0][0]
		return deco

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

G_BufferAnalyzer = BufferAnalyzer(True)

class BufferAccumulator:
	def __init__(self):
		self.m_currentBuffer = None
		self.m_informations_classes = {}

	# When the current buffer has been reassembled.
	# This ensures that as few information as possible is stored.
	def AnalyseCompleteBuffer(self,aBuffer):
		bufClass = G_BufferAnalyzer.GetBufferClass(aBuffer)
		if bufClass:
			# Maybe we have several different identifications.
			try:
				self.m_informations_classes[bufClass] += 1
			except KeyError:
				self.m_informations_classes = { bufClass : 1 }

	def GetContentClass(self):
		maxCla = None
		if self.m_informations_classes:
			maxNum = 0
			for cla in self.m_informations_classes:
				num = self.m_informations_classes[cla]
				if maxNum < num:
					maxNum = num
					maxCla = cla
		print("maxNum=%d"%maxNum)
		return maxCla


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


def TestAnalysis():
	acc = BufferAccumulator()

	tstdat = [
		("auth something","ftp"),
		("qsldjhfqlksjdhflqjshd",None),
		("SELECT * FROM a_table","oracle"),
		("insert into something values('a','b')","oracle"),
	]


	for tstPair in tstdat:
		acc.AppendIOBuffer(tstPair[0])
		aCla = acc.GetContentClass()
		sys.stdout.write("%20s %20s\n"%(aCla,tstPair[1]))


# It should be modular enough so that he creation of CIM entites could be in a separate HTTP server,
# and this could work on tcpdump socket content.

if __name__ == '__main__':
    TestAnalysis()