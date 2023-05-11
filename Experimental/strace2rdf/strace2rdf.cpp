/*********************************************************************
** Strace To RDF
**
** "Survol : The map is the territory".
**
** Copyright Primhill Computers 2023
**********************************************************************/

#include <unistd.h>
#include <sys/time.h>
#include <string.h>

#include <iostream>
#include <vector>
#include <string>
#include <iterator>
#include <exception>
#include <map>
#include <fstream>
#include <stack>
#include <memory>

using namespace std;

template<class T>
static void append_vector(vector<string> & target, const T & source) {
	copy(source.begin(), source.end(), back_inserter(target));
}

enum CallState {INVALID, SIGNAL, PLAIN, UNFINISHED, RESUMED}; 

static const size_t NOT_UNFINISHED = size_t(~0);

/*
If it finishes with the string indicating an unfinished call.
This returns the offset just after the end of the last argument.
*/
static size_t isUnfinished(const char * line) {
	static const char strUnfinished[] = "<unfinished ...>";
	size_t len = strlen(line);

	// The string is too short.
	if(len < sizeof(strUnfinished) - 1) return NOT_UNFINISHED;
	size_t end_offset = len - sizeof(strUnfinished) + 1;
	if(0 != strcmp(strUnfinished, line + end_offset)) {
		// It does not end with "<unfinished ...";
		return NOT_UNFINISHED;
	}

	// Now, step back until finding the last non-space and non-comma char,
	// Which is the last char of the last argument.
	if(end_offset) {
		for(--end_offset; end_offset; --end_offset) {
			char chr = line[end_offset];
			//cout << "    chr=" << chr << endl;
			if(chr == ' ') continue;
			if(chr == ',') {
				if(end_offset > 0)
					--end_offset;
			}
			break;
		}
		if(end_offset > 0)
			++end_offset;
	}
	if( (line[end_offset] != ' ') && (line[end_offset] != ',') && (line[end_offset] != '<')) {
		throw runtime_error(" inconsistency");
	}
	return end_offset;
}

/*
This extracts the function name so the right parser can be created.
The line might start or not, with the pid.
19:58:35.830990 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3b1ca779d0) = 5557 <0.000185>
[pid  4233] 19:58:35.831382 close(3<pipe:[52233]>) = 0 <0.000016>
*/
class PreparsedLine {
	// Today's timestamp.
	double m_seconds;

	void ParseTimestamp(const char * time_start) {
		// It must point to a string like "19:58:35.834615"

		int hour, minutes;
		double seconds;
		int ret = sscanf(time_start, "%d:%d:%lf", &hour, &minutes, &seconds);
		if(ret != 3) {
			throw std::runtime_error(string(" Invalid time format:") + time_start);
		}
		m_seconds = hour * 24 * 3600 + minutes * 60 + seconds;
	};
public:
	string function_name;
	size_t args_offset; // Points to the open parenthesis after the function name.
	int processid; // -1 if this is the current process.
	CallState m_callstate;

	PreparsedLine()
	: processid(-1)
	, m_callstate(INVALID) {}

	PreparsedLine(const string & line) {
		const char * line_start = line.c_str();
		static const char pid_prefix[] = "[pid ";
		int time_offset; // Beginning of the time-stamp.
		if(0 == strncmp(line_start, pid_prefix, sizeof(pid_prefix) - 1) ) {
			int pos_end;
			int ret_scan = sscanf(line_start + sizeof(pid_prefix), "%d] %n", &processid, &pos_end);
			if(1 != ret_scan) {
				throw runtime_error("Cannot parse pid from:" + line);
			}
			if(processid < 0) {
				throw runtime_error("Invalid pid from:" + line);
			}
			time_offset = sizeof(pid_prefix) + pos_end;
		} else {
			processid = -1;
			time_offset = 0;
		}
		ParseTimestamp(line_start + time_offset);
		const char * time_end = strchr(line_start + time_offset, ' ');
		if(time_end == nullptr) {
			throw std::runtime_error("No timestamp:" + line);
		}

		const char * function_valid_chars = "abcdefghijklmnopqrstuvwxyz0123456789_";
		const char * function_start = time_end + 1;
		
		// Maybe this is not a function call.
		const char sig_chld[] = "--- SIGCHLD";
		if(0 == strncmp(function_start, sig_chld, sizeof(function_start) - 1)) {
			m_callstate = SIGNAL;
			return;
		}
		
		// A regular expression would also work.
		size_t longest_ascii = strspn(function_start, function_valid_chars);
		const char * function_end = function_start + longest_ascii;
		bool is_valid_function = *function_end == '(';
		// const char * function_end = strchr(function_start, '(');
		/*
			[pid  5557] 19:58:35.831752 close(4<pipe:[52233]> <unfinished ...>
			[pid  5557] 19:58:35.831817 <... close resumed> ) = 0 <0.000041>
		*/
		
		/*
			[pid  4233] 19:58:35.831781 wait4(-1,  <unfinished ...>
			19:58:35.841846 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 5557 <0.010057>
			19:58:35.842034 wait4(-1, 0x7fffa5fca650, WNOHANG|WSTOPPED|WCONTINUED, NULL) = -1 ECHILD (No child processes) <0.000007>
			[pid  4233] 19:58:40.706014 wait4(-1,  <unfinished ...>
			19:58:46.024321 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 5562 <5.318296>
			19:58:46.024677 wait4(-1, 0x7fffa5fca650, WNOHANG|WSTOPPED|WCONTINUED, NULL) = -1 ECHILD (No child processes) <0.000013>
			[pid  4233] 19:58:51.281110 wait4(-1,  <unfinished ...>
			19:58:51.790724 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 5573 <0.509606>
			19:58:51.790942 wait4(-1, 0x7fffa5fca650, WNOHANG|WSTOPPED|WCONTINUED, NULL) = -1 ECHILD (No child processes) <0.000007>
			[pid  4233] 19:59:02.345211 wait4(-1,  <unfinished ...>
			19:59:07.208177 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 5584 <4.862956>
			19:59:07.208490 wait4(-1, 0x7fffa5fca650, WNOHANG|WSTOPPED|WCONTINUED, NULL) = -1 ECHILD (No child processes) <0.000010>
			[pid  4233] 19:59:20.542876 wait4(-1,  <unfinished ...>
			19:59:20.964701 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 5602 <0.421816>
			19:59:20.964728 wait4(-1, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 5601 <0.000032>
			19:59:20.965024 wait4(-1, 0x7fffa5fca610, WNOHANG|WSTOPPED|WCONTINUED, NULL) = -1 ECHILD (No child processes) <0.000007>
		*/
		bool unfinished = isUnfinished(function_start) != NOT_UNFINISHED;
		const char str_resumed[] = " resumed>";
		bool resumed = nullptr != strstr(function_start, str_resumed);
		if(unfinished && resumed) {
			throw runtime_error("Cannot be unfinished and resumed");
		}
		if(resumed) {
			m_callstate = RESUMED;
			if(is_valid_function) {
				throw runtime_error("Function name not be valid if resumed.");
			}
			// Extract function from "<... wait4 resumed>", to be sure this is the right call.
			const char str_dots[] = "<... ";
			const char * ptr_dots = strstr(function_start, str_dots);
			if(ptr_dots == nullptr) {
				throw runtime_error(string("Cannot find:") + str_dots);
			}
			function_start += sizeof(str_dots) - 1;
			size_t longest_ascii = strspn(function_start, function_valid_chars);
			function_end = function_start + longest_ascii;
			if(0 != strncmp(function_end, str_resumed, sizeof(str_resumed) - 1)) {
				throw runtime_error(string("Cannot find:") + str_resumed);
			}
		} else {
			m_callstate = unfinished ? UNFINISHED : PLAIN;
			if(!is_valid_function) {
				throw runtime_error(
					"Function name must be valid if unfinished or ok. longest_ascii=" + to_string(longest_ascii)
					+ "function_start=" + string(function_start));
			}
		}
		function_name.assign(function_start, function_end);
		args_offset = function_end - line_start;
		
		switch(m_callstate) {
			case UNFINISHED:
				cout << "UNFINISHED " << function_name << " pid=" << processid << endl;
				break;
			case RESUMED:
				cout << "RESUMED " << function_name << " pid=" << processid << endl;
				break;
		}
	}
};

static char closing(char chr) {
	switch(chr) {
		case '(': return ')';
		case '{': return '}';
		case '[': return ']';
		case '<': return '>';
	}
	throw runtime_error(string("Invalid char:") + chr);
}

static vector<string> ArgumentsParser(const string & line, size_t start_offset, bool verbose) {
	if(verbose) {
		cout << "LINE=" << line << "\n";
	}
	if(line[start_offset] != '(') {
		throw std::runtime_error("Wrong offset:" + line);
	}

	const char * args_start = line.c_str() + start_offset;
	size_t end_offset = isUnfinished(args_start);
	if(end_offset == NOT_UNFINISHED) {
		// end_offset must be the last closing parenthesis. We can find it anyway.
	} else {
		cout << "UNFINISHED STRIPPED:" << string(args_start, args_start + end_offset) << "." << endl;
	}

	bool in_quotes = false;
	int balance_parenthesis = 1;
	vector<string> args;
	string current_arg;
	bool still_running = true;
	stack<char> enclosers;
	enclosers.push(')');
	for(size_t index = 1; still_running && (index < end_offset); ++index) {
		const char chr = args_start[index];
		if(in_quotes) {
			if(chr == '"') {
				in_quotes = false;
			}
			current_arg += chr;
			continue;
		}
		switch(chr) {
			case ')': case '}': case ']': case '>':
				--balance_parenthesis;
				if(enclosers.top() != chr) {
					throw runtime_error(string("Should be closing characters:") + enclosers.top() + string(" instead of:") + chr);
				}
				enclosers.pop();
				if(balance_parenthesis == 0) {
					still_running = false;
				} else {
					current_arg += chr;
				}
				break;
			case '(': case '{': case '[': case '<':
				++balance_parenthesis;
				enclosers.push(closing(chr));
				current_arg += chr;
				break;
			case '"':
				in_quotes = true;
				current_arg += chr;
				break;
			case ',':
				if(balance_parenthesis == 1) {
					args.push_back(current_arg);
					current_arg.clear();
				} else {
					current_arg += chr;
				}
				break;
			default:
				current_arg += chr;
				break;
		}
	}
	
	// It might be unfinished like "[pid  4233] 19:58:35.831781 wait4(-1,  <unfinished ...>"
	// or "[pid  5557] 19:58:35.831752 close(4<pipe:[52233]> <unfinished ...>"
	if(balance_parenthesis == 1) {
		cout << "Unfinished" << endl;
	}
	args.push_back(current_arg);
	/*
	cout << "ARGS" << endl;
	for(auto arg : args) {
		cout << "    " << arg << "." << endl;
	}
	*/
	return args;
}

/*******************************************************************************
**
** Internal tests.
**
*******************************************************************************/

struct test_definition {
	const char * input;
	const vector<const char *> outputs;
	test_definition(const char * the_input, initializer_list<const char *> the_outputs)
	: input(the_input)
	, outputs(the_outputs)
	{}
	
	void test() {
		cout << "Input=" << input << endl;
		vector<string> args = ArgumentsParser(input, 0, true);
		copy(outputs.begin(), outputs.end(), ostream_iterator<const char *>(cout, "+"));
		cout << endl;
		copy(args.begin(), args.end(), ostream_iterator<const string &>(cout, "+"));
		cout << endl;
		
		if(args.size() != outputs.size() ) {
			throw runtime_error("Different sizes");
		}
		for(size_t index = 0; index < outputs.size(); ++index) {
			if( args[index] != outputs[index]) {
				throw runtime_error("Different args");
			}
		}
	}
};
static const test_definition test_args_parsing[] = {
	{"(xyz)", {"xyz"}},
	{"(x,y,z)", {"x", "y", "z"}},
	{"(x,\"y\",z)", {"x", "\"y\"", "z"}},
	{"(x,(y),z)", {"x", "(y)", "z"}},
	{"(x,(y1,y2),z)", {"x", "(y1,y2)", "z"}},
	{"(7</usr/share>, {st_mode=S_IFREG|0644, st_size=3678, ...}) = 0 <0.000059>",
		{"7</usr/share>", " {st_mode=S_IFREG|0644, st_size=3678, ...}"}},
	{"(AT_FDCWD, \"/usr/coreutils.moz\", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000031>",
		{"AT_FDCWD", " \"/usr/coreutils.moz\"", " O_RDONLY"}},
	{"(x,\"y[a\",z)", {"x", "\"y[a\"", "z"}},
	{"(x,\"y}a\",z)", {"x", "\"y}a\"", "z"}},
};

static void test_parsing() {
	printf("Internal test start.\n");
	for(auto one_test : test_args_parsing) {
		one_test.test();
	}
	printf("Parsing test end : OK.\n");
}

static const struct {
	size_t unfinished;
	const char * line;
} tests_unfinished[] = {
	{ 0, "<unfinished ...>"},
	{ 3, "xyz<unfinished ...>"},
	{ 3, "xyz <unfinished ...>"},
	{ 3, "xyz  <unfinished ...>"},
	{ 3, "xyz, <unfinished ...>"},
	{ 4, "xyz , <unfinished ...>"},
	{ 8, "wait4(-1,  <unfinished ...>"},
	{ 21, "close(4<pipe:[52233]> <unfinished ...>"},
	{ 0, " <unfinished ...>"},
	{ 0, ", <unfinished ...>"},
	{ NOT_UNFINISHED, "<unfinished ...> "},
	{ NOT_UNFINISHED, "<unfinished>"},
	{ NOT_UNFINISHED, "abc"},
};

static void test_unfinished() {
	for(auto tst : tests_unfinished) {
		size_t ret = isUnfinished(tst.line);
		cout << "TST:" << tst.line << " Expected=" << tst.unfinished << " Actual=" << ret << endl;
		if(tst.unfinished == ret && ret != NOT_UNFINISHED) {
			cout << "[" << string(tst.line, tst.line + ret) << "]" << endl;
		}
		if( ret != tst.unfinished) {
			throw runtime_error(string("Wrong unfinished value:") + tst.line);
		}
	}
	printf("Unfinished detection test end : OK.\n");
}

static const struct {
	int pid;
	string function_name;
	string line;
} tests_preparsed[] = {
	{ -1, "clone", "19:58:35.830990 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3b1ca779d0) = 5557 <0.000185>"  },
	{ 4233, "close", "[pid  4233] 19:58:35.831382 close(3<pipe:[52233]>) = 0 <0.000016>"},
};

static void test_preparsed() {
	for(auto tst : tests_preparsed) {
		cout << "PreparsedLine:" << tst.line << endl;
		PreparsedLine preparsed(tst.line);
		if(preparsed.processid != tst.pid) {
			throw runtime_error("Wrong pid:" + to_string(preparsed.processid));
		}
		if(preparsed.function_name != tst.function_name) {
			throw runtime_error("Wrong function:" + preparsed.function_name);
		}
	}
	printf("Preparsed test end : OK.\n");
}

static void test_internal() {
	test_parsing();
	test_unfinished();
	test_preparsed();
	printf("Internal test end : OK.\n");
}

/*******************************************************************************
**
** Writing triples.
**
*******************************************************************************/

/*
<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF
   xmlns:love="http://love.com#"
   xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
>
  <rdf:Description rdf:about="http://love.com/lovers/john">
    <love:hasCuteName>Johnny Boy</love:hasCuteName>
  </rdf:Description>
</rdf:RDF>



  <rdf:Description rdf:about="http://rchateau-hp:8000/survol/entity_dirmenu_only.py">
    <rdfs:seeAlso rdf:resource="http://rchateau-hp:8000/survol/sources_types/enumerate_CIM_Process.py?xid=.PLAINTEXTONLY"/>
    <rdfs:seeAlso rdf:resource="RabbitMQ%20concepts?mode=cluster"/>
  </rdf:Description>

"http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_DataFile.Name=C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/./UnitTests/mineit_find_grep.strace.docker/home">
    <ns1:Category>Others</ns1:Category>
    <rdf:type rdf:resource="http://www.primhillcomputers.com/survol#CIM_DataFile"/>
    <ns1:Name>C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/./UnitTests/mineit_find_grep.strace.docker/home</ns1:Name>
    <ns1:FileName>home</ns1:FileName>
  </rdf:Description>

*/


class RdfOutput {
	ostream *m_ostream;
	ofstream m_ofstream;
	bool m_must_close;
public:
	RdfOutput(const string &output_file) {
		if(output_file.empty() ) {
			m_ostream = &cout;
			m_must_close = false;
		} else {
			m_ofstream.open(output_file);
			m_ostream = &m_ofstream;
			m_must_close = true;
		}
		
		*m_ostream << R"(\
<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF
   xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
   xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#"
   xmlns:survol="http://www.primhillcomputers.com/survol#"
>
)";
	}

	~RdfOutput() {
		*m_ostream << R"(\
</rdf:RDF>
)";
		if(m_must_close) {
			m_ofstream.close();
		}
	}

	void WriteTriple(const string &subject, const string &property, const string &object) {
/*
		*m_ostream <<     "<rdf:Description rdf:about=\"" << subject << "\">" << endl;
    <love:hasCuteName>Johnny Boy</love:hasCuteName>
		*m_ostream <<     "</rdf:Description>" << endl;	
*/
	}
};

/*******************************************************************************
**
** Types of arguments of system calls.
**
*******************************************************************************/
struct ArgumentType {
	virtual string ToRdf(const string & property, const string & input_txt) const = 0;
};

template<class DerivedArgument>
struct ArgumentTypeWrapper : public ArgumentType {
	static const ArgumentType & ArgDef() {
		static const DerivedArgument arg;
		return arg;
	}
};

struct SystemCallArgument_ProcessId : public ArgumentTypeWrapper<SystemCallArgument_ProcessId> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return property + "=" + input_txt;
	}
};
struct SystemCallArgument_IntPtr : public ArgumentTypeWrapper<SystemCallArgument_IntPtr> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return property + "=" + input_txt;
	}
};
struct SystemCallArgument_Int : public ArgumentTypeWrapper<SystemCallArgument_Int> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return property + "=" + input_txt;
	}
};
struct SystemCallArgument_RusagePtr : public ArgumentTypeWrapper<SystemCallArgument_RusagePtr> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return property + "=" + input_txt;
	}
};
struct SystemCallArgument_Fd : public ArgumentTypeWrapper<SystemCallArgument_Fd> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return property + "=" + input_txt;
	}
};
struct SystemCallArgument_Addr : public ArgumentTypeWrapper<SystemCallArgument_Addr> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return property + "=" + input_txt;
	}
};
struct SystemCallArgument_AddrLen : public ArgumentTypeWrapper<SystemCallArgument_AddrLen> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return property + "=" + input_txt;
	}
};
struct SystemCallArgument_PathName : public ArgumentTypeWrapper<SystemCallArgument_PathName> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return property + "=" + input_txt;
	}
};
struct SystemCallArgument_ArgV : public ArgumentTypeWrapper<SystemCallArgument_ArgV> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return property + "=" + input_txt;
	}
};
struct SystemCallArgument_EnvP : public ArgumentTypeWrapper<SystemCallArgument_EnvP> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return property + "=" + input_txt;
	}
};
struct SystemCallArgument_Flags : public ArgumentTypeWrapper<SystemCallArgument_Flags> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return property + "=" + input_txt;
	}
};
struct SystemCallArgument_Mode : public ArgumentTypeWrapper<SystemCallArgument_Mode> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return property + "=" + input_txt;
	}
};

typedef initializer_list< pair<const char *, const ArgumentType &> > FunctionSignature;

/*******************************************************************************
**
** Base class of system calls.
**
*******************************************************************************/
/*
Typical line displayed by the command strace:
17:17:06.968628 fstat(7</usr/share/zoneinfo/Europe/London>, {st_mode=S_IFREG|0644, st_size=3678, ...}) = 0 <0.000021>
*/
class STraceCall {
protected:
	vector<string> parsed_arguments;
public:
	STraceCall(const string & line, const PreparsedLine & preparsedLine) {
		const char * line_start = line.c_str();
		const char * time_end = strchr(line_start, ' ');
		if(time_end == nullptr) {
			throw std::runtime_error("No timestamp:" + line);
		}
		try {
			parsed_arguments = ArgumentsParser(line, preparsedLine.args_offset, true);
		} catch(const exception & exc) {
			cerr << "Line=" << line << endl;
			throw;
		}
	}
	
	virtual const char * function() const = 0;
	virtual const FunctionSignature & Signature() const {
		static const FunctionSignature tmp;
		return tmp; // throw runtime_error("Not implemented yet");
	}
	virtual size_t MinimumArgumentsNumber() const {
		return Signature().size();
	}
	
	virtual void WriteTriples(RdfOutput & rdfOutput) const {
		throw runtime_error("Not implemented yet");
	};

	virtual void WriteCall(RdfOutput & rdfOutput, bool verbose) {
		const auto & argsDefs = Signature();
		size_t minArgs = MinimumArgumentsNumber();
		if(verbose) {
			printf("Signature=%d Minimum=%d\n", (int)argsDefs.size(), (int)minArgs);
		}
		size_t index = 0;
		for(const auto & oneArg : argsDefs) {
			if(index >= parsed_arguments.size()) {
				if(index >= minArgs) {
					break;
				} else {
					throw runtime_error("Not enough arguments");
				}
			}
			string value = parsed_arguments[index];
			if(verbose) {
				cout << "First / Value=" << oneArg.first << " " << value << endl;
			}
			string asStr = oneArg.second.ToRdf(oneArg.first, value);
			cout << "    " << asStr << endl;
			++index;
		}
	}


	void Display() const {
		for(const string & arg: parsed_arguments) {
			cout << "\t" << arg << endl;
		}
	}
	
	void MergeWithResumed(const PreparsedLine & resumed) {
		if(resumed.function_name != function()) {
			throw runtime_error(string("Cannot merge ") + function() + " with " + resumed.function_name);
		}
		cout << "MERGING " << function() << endl;
	}
};

class STraceFactory {
public:
	typedef shared_ptr<STraceCall> (*Generator)(const string & line, const PreparsedLine & preparsedLine);

	static shared_ptr<STraceCall> factory(const string & line);
};
	
/*******************************************************************************
**
** Interesting system calls.
**
*******************************************************************************/

// 07:46:32.057886 connect(9<socket:[1552]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory) <0.000123>
class STraceCall_connect : public STraceCall {
public:
	STraceCall_connect(const string & line, const PreparsedLine & preparsedLine)
	: STraceCall(line, preparsedLine) {
	}
	const char * function() const override { return "connect";}
	
	// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	const FunctionSignature & Signature() const override {
		static const FunctionSignature sign {
			{ "sockfd",  SystemCallArgument_Fd::ArgDef() },
			{ "addr",    SystemCallArgument_Addr::ArgDef() },
			{ "addrlen", SystemCallArgument_AddrLen::ArgDef() },
		};
		return sign;
	}
};

// [pid  5562] 19:58:40.706447 execve("/usr/bin/top", ["top"], [/* 36 vars */]) = 0 <0.031053>
class STraceCall_execve : public STraceCall {
public:
	STraceCall_execve(const string & line, const PreparsedLine & preparsedLine)
	: STraceCall(line, preparsedLine) {
	}
	const char * function() const override { return "execve";}
	// int execve(const char *pathname, char *const argv[], char *const envp[]);
	const FunctionSignature & Signature() const override {
		static const FunctionSignature sign {
			{ "pathname", SystemCallArgument_PathName::ArgDef() },
			{ "argv",     SystemCallArgument_ArgV::ArgDef() },
			{ "envp",     SystemCallArgument_EnvP::ArgDef() },
		};
		return sign;
	}
};

class STraceCall_fchdir : public STraceCall {
public:
	STraceCall_fchdir(const string & line, const PreparsedLine & preparsedLine)
	: STraceCall(line, preparsedLine) {
	}
	const char * function() const override { return "fchdir";}
	// int fchdir(int fildes);
	const FunctionSignature & Signature() const override {
		static const FunctionSignature sign {
			{ "fildes", SystemCallArgument_Fd::ArgDef() },
		};
		return sign;
	}
};


class STraceCall_open : public STraceCall {
public:
	STraceCall_open(const string & line, const PreparsedLine & preparsedLine)
	: STraceCall(line, preparsedLine) {
	}
	const char * function() const override { return "open";}
	// int open(const char *pathname, int flags);
	// int open(const char *pathname, int flags, mode_t mode);
	const FunctionSignature & Signature() const override {
		static const FunctionSignature sign {
			{ "pathname", SystemCallArgument_PathName::ArgDef() },
			{ "flags",    SystemCallArgument_Flags::ArgDef() },
			{ "mode",     SystemCallArgument_Mode::ArgDef() },
		};
		return sign;
	}
	size_t MinimumArgumentsNumber() const override {
		return 2;
	}
};

// [pid  5562] 19:58:40.737710 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000011>
class STraceCall_openat : public STraceCall {
public:
	STraceCall_openat(const string & line, const PreparsedLine & preparsedLine)
	: STraceCall(line, preparsedLine) {
	}
	const char * function() const override { return "openat";}
	// int openat(int fd, const char *path, int oflag, ...);
	const FunctionSignature & Signature() const override {
		static const FunctionSignature sign {
			{ "fd", SystemCallArgument_Fd::ArgDef() },
			{ "pathname", SystemCallArgument_PathName::ArgDef() },
			{ "oflag",    SystemCallArgument_Flags::ArgDef() },
			{ "mode",     SystemCallArgument_Mode::ArgDef() },
		};
		return sign;
	}
	size_t MinimumArgumentsNumber() const override {
		return 2;
	}
};

/* This call is a special case because if it is unfishied in a process,
it is resumed in the process given as first parameter. */
class STraceCall_wait4 : public STraceCall {
public:
	STraceCall_wait4(const string & line, const PreparsedLine & preparsedLine)
	: STraceCall(line, preparsedLine) {
	}
	const char * function() const override { return "wait4";}
	
	// pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage);
	const FunctionSignature & Signature() const override {
		static const FunctionSignature sign {
			{ "pid", SystemCallArgument_ProcessId::ArgDef() },
			{ "wstatus", SystemCallArgument_IntPtr::ArgDef() },
			{ "options", SystemCallArgument_Int::ArgDef() },
			{ "rusage",  SystemCallArgument_RusagePtr::ArgDef() },
		};
		return sign;
	}
	
	int expected_resuming_pid() const {
		if(parsed_arguments.size() != 1) {
			throw runtime_error("No argument for wait4");
		}
		return stoi(parsed_arguments[0]);
	}
};

template<class Derived>
shared_ptr<STraceCall> GenerTmpl(const string &line, const PreparsedLine & preparsedLine) {
	return make_shared<Derived>(line, preparsedLine);
}

// Most system calls are not taken into account. However, their list might suggest more dependencies.
map<string, STraceFactory::Generator> dict = {
	{"accept", nullptr },
	{"arch_prctl", nullptr },
	{"bind", nullptr },
	{"brk", nullptr },
	{"clone", nullptr },
	{"close", nullptr },
	{"connect", GenerTmpl<STraceCall_connect> },
	{"dup", nullptr },
	{"dup2", nullptr },
	{"dup3", nullptr },
	{"epoll_create1", nullptr },
	{"epoll_ctl", nullptr },
	{"epoll_wait", nullptr },
	{"eventfd2", nullptr },
	{"execve", GenerTmpl<STraceCall_execve> },
	{"exit", nullptr },
	{"exit_group", nullptr },
	{"faccessat", nullptr },
	{"fadvise64", nullptr },
	{"fallocate", nullptr },
	{"fchdir", GenerTmpl<STraceCall_fchdir> },
	{"fchmod", nullptr },
	{"fchown", nullptr },
	{"fcntl", nullptr },
	{"fstat", nullptr },
	{"fstatfs", nullptr },
	{"fsync", nullptr },
	{"ftruncate", nullptr },
	{"getdents", nullptr },
	{"getdents64", nullptr },
	{"getpeername", nullptr },
	{"getsockname", nullptr },
	{"getsockopt", nullptr },
	{"inotify_add_watch", nullptr },
	{"inotify_init1", nullptr },
	{"ioctl", nullptr },
	{"listen", nullptr },
	{"lseek", nullptr },
	{"madvise", nullptr },
	{"mlock", nullptr },
	{"mmap", nullptr },
	{"mprotect", nullptr },
	{"munmap", nullptr },
	{"newfstatat", nullptr },
	{"open", GenerTmpl<STraceCall_open> },
	{"openat", GenerTmpl<STraceCall_openat> },
	{"pipe", nullptr },
	{"pipe2", nullptr },
	{"poll", nullptr },
	{"ppoll", nullptr },
	{"pread64", nullptr },
	{"pselect6", nullptr },
	{"pwrite64", nullptr },
	{"read", nullptr },
	{"readahead", nullptr },
	{"recvfrom", nullptr },
	{"recvmsg", nullptr },
	{"shmat", nullptr },
	{"shmdt", nullptr },
	{"shmget", nullptr },
	{"shutdown", nullptr },
	{"select", nullptr },
	{"sendmmsg", nullptr },
	{"sendmsg", nullptr },
	{"sendto", nullptr },
	{"setsockopt", nullptr },
	{"socket", nullptr },
	{"socketpair", nullptr },
	{"unshare", nullptr },
	{"vfork", nullptr },
	{"wait4", GenerTmpl<STraceCall_wait4> },
	{"write", nullptr },
	{"writev", nullptr },
};

static map<int, shared_ptr<STraceCall>> unfinished_calls;


static shared_ptr<STraceCall> GenerateCallFromParsed(const PreparsedLine & preparsedLine, const string & line) {
	auto iter = dict.find(preparsedLine.function_name);
	if(iter == dict.end()) {
		throw runtime_error("Cannot find function:" + preparsedLine.function_name);
	}
	STraceFactory::Generator gener = iter->second;
	if(gener == nullptr) {
		// throw runtime_error("Disabled function:" + preparsedLine.function_name);
		return shared_ptr<STraceCall>();
	}
	// printf("INIT after l=%d KEY=%s\n", (int)dict.size(), preparsedLine.function_name.c_str());
	return gener(line, preparsedLine);
}


shared_ptr<STraceCall> STraceFactory::factory(const string & line) {
	PreparsedLine preparsedLine(line);
	switch(preparsedLine.m_callstate) {
		case UNFINISHED: {
			auto found_preparsed = unfinished_calls.find(preparsedLine.processid);
			if(found_preparsed != unfinished_calls.end()) {
				throw runtime_error("There should not be two unfinished calls for the same pid");
			}
			shared_ptr<STraceCall> ptrUnfinished = GenerateCallFromParsed(preparsedLine, line);

			// Special case for "wait4" because if it is unfinished in a given process,
			// it might be resumed in the process given as first parameter of wait4().
			const STraceCall_wait4 * ptrWait4 = dynamic_cast<const STraceCall_wait4 *>(ptrUnfinished.get());
			int resuming_pid;
			if(ptrWait4 != nullptr) {
				if(preparsedLine.function_name != "wait4") {
					throw runtime_error("Inconsistency with wait4");
				}
				resuming_pid = ptrWait4->expected_resuming_pid();
			} else {
				resuming_pid = preparsedLine.processid;
			}
			unfinished_calls[resuming_pid] = ptrUnfinished;
			// Do not return a finished call.
			return shared_ptr<STraceCall>();
		}
		break;
		case PLAIN: {
			return GenerateCallFromParsed(preparsedLine, line);
		}
		case RESUMED: {
			auto found_preparsed = unfinished_calls.find(preparsedLine.processid);
			if(found_preparsed == unfinished_calls.end()) {
				// This can happen : strace misses some calls.
				throw runtime_error(
					"Cannot find unfinished call. Function=" + preparsedLine.function_name
					+ " Pid=" + to_string(preparsedLine.processid));
			}
			shared_ptr<STraceCall> ptrUnfinished = found_preparsed->second;
			if(ptrUnfinished) {
				ptrUnfinished->MergeWithResumed(preparsedLine);
			}
			unfinished_calls.erase(found_preparsed);
			return ptrUnfinished;
		}
		case SIGNAL: {
			return shared_ptr<STraceCall>();
		}
	}
	throw runtime_error("Invalid call state");
}


static void process_line(RdfOutput & rdfOutput, const string &line, size_t line_number, bool verbose) {
	if(verbose) {
		cout << line_number << "\t" << line << endl;
	}
	try {
		shared_ptr<STraceCall> ptr = STraceFactory::factory(line);
		if(ptr.get() == nullptr) {
			return;
		}
		if(verbose) {
			cout << "Function=" << ptr->function() << endl;
			ptr->Display();
		}
		ptr->WriteCall(rdfOutput, verbose);
	} catch( const std::exception & exc) {
		printf("Line %d Caught:%s\n", (int)line_number, exc.what());
		printf("RET=%s\n", line.c_str());
	}
}

/*******************************************************************************
**
** Execution of strace in a subprocess.
**
*******************************************************************************/

static vector<string> strace_command() {
/*
    def build_trace_command(self, external_command, a_pid):
        # -f  Trace  child  processes as a result of the fork, vfork and clone.
        trace_command = ["strace", "-q", "-qq", "-f", "-tt", "-T", "-s", G_StringSize]

        if self.deprecated_version():
            trace_command += ["-e", "trace=desc,ipc,process,network"]
        else:
            trace_command += ["-y", "-yy", "-e", "trace=desc,ipc,process,network,memory"]

        if external_command:
            # Run tracer process as a detached grandchild, not as parent of the tracee. This reduces the visible
            # effect of strace by keeping the tracee a direct child of the calling process.
            # It might fail with the error:
            # strace: Could not attach to process. If your uid matches the uid of the target process,
            # check the setting of /proc/sys/kernel/yama/ptrace_scope, or try again as the root user.
            # For more details, see /etc/sysctl.d/10-ptrace.conf: Operation not permitted
            # strace: attach: ptrace(PTRACE_ATTACH, 498): Operation not permitted
            ### trace_command += ["-D"]
            trace_command += external_command
        else:
            trace_command += ["-p", a_pid]
        return trace_command
*/
	vector<string> command{"/usr/bin/strace", "-q", "-qq", "-f", "-tt", "-T", "-s", "10000"};
	const bool is_deprecated = false;
	vector<string> dependent_options{is_deprecated
	? "-e", "trace=desc,ipc,process,network"
	: "-y", "-yy", "-e", "trace=desc,ipc,process,network,memory"};
	append_vector(command, dependent_options);
	return command;
}

static string readline(int fd) {
	string result;
	for(;;) {
		char c;
	    ssize_t ret = read(fd, &c, 1);
		if(ret == 0) break;
		if(c == '\n') break;
		result += c;
	}
	return result;
}

static int popen3(RdfOutput & rdfOutput, int fd[3], char * const * cmd, bool verbose) {
    int i, e;
    int p[3][2];
    pid_t pid;
    // set all the FDs to invalid
    for(i=0; i<3; i++)
        p[i][0] = p[i][1] = -1;
    // create the pipes
    for(int i=0; i<3; i++)
        if(pipe(p[i]))
            return -1;
    // and fork
    pid = fork();
    if(-1 == pid)
        return -1;
    // in the parent?
    if(pid) {
        close(p[STDIN_FILENO][0]);
        close(p[STDOUT_FILENO][1]);

        fd[STDERR_FILENO] = p[STDERR_FILENO][0];
        close(p[STDERR_FILENO][1]);

		for(size_t line_number = 1;; ++line_number) {
			string ret = readline(fd[STDERR_FILENO]);
			if(ret.empty()) break;
			process_line(rdfOutput, ret, line_number, verbose);
		}
		printf("END STDERR end\n");
        // success
        return 0;
    } else {
        // child
//        dup2(p[STDIN_FILENO][0],STDIN_FILENO);
//        close(p[STDIN_FILENO][1]);

		
        //dup2(p[STDOUT_FILENO][1],STDOUT_FILENO);
        //close(p[STDOUT_FILENO][0]);

		printf("+++++++++++++++++ STDERR_FILENO=%d\n", STDERR_FILENO);
        dup2(p[STDERR_FILENO][1],STDERR_FILENO);
        close(p[STDERR_FILENO][0]);

        execv(cmd[0], cmd);
        // if we are there, then we failed to launch our program
        perror("Could not launch");
        fprintf(stderr," \"%s\"\n",*cmd);
        _exit(EXIT_FAILURE);
    }

    // preserve original error
    e = errno;
    for(i=0; i<3; i++) {
        close(p[i][0]);
        close(p[i][1]);
    }
    errno = e;
    return -1;
}

static int execute_command(RdfOutput & rdfOutput, const vector<string> & command, bool verbose) {
	int fd[3];
	const char ** ptr_chars = new const char *[command.size() + 1];
	for(size_t index = 0; index < command.size(); ++index) {
		ptr_chars[index] = command[index].c_str();
	}
	ptr_chars[command.size()] = nullptr;

	printf("Command:");
	fflush(stdout);
	copy(ptr_chars, ptr_chars + command.size(), ostream_iterator<const char *>(cout, " "));
	cout.flush();
	printf("\n");
	int ret = popen3(rdfOutput, fd, (char * const *)ptr_chars, verbose);
	delete[] ptr_chars;
	return ret;
}

/*******************************************************************************
**
** Replaying a log file.
**
*******************************************************************************/
static int replay_strace_logfile(RdfOutput & rdfOutput, const string & replay_log, bool verbose) {
	ifstream infile(replay_log);
	string input_line;
	size_t line_number = 0;
	while(infile.good()){
		getline(infile, input_line);
		process_line(rdfOutput, input_line, line_number, verbose);
		++line_number;
	}
	return 0;
}

/*******************************************************************************
**
** Processing the command line.
**
*******************************************************************************/

class CommandExecutor {
	vector<string> m_command;
	string m_input_file;
	bool m_verbose;


public:
	/* The parameters can be a Linux command to execute in strace, or an input file to replay a session.*/
	CommandExecutor(vector<string> command, bool verbose) : m_command(command), m_verbose(verbose) {}
	
	/* This is the log of the execution of a previous strace run. */
	CommandExecutor(string input_file, bool verbose) : m_input_file(input_file), m_verbose(verbose) {}
	
	void Execute(RdfOutput & rdfOutput) {
		if(m_input_file.empty()) {
			if(m_command.empty()) {
				throw runtime_error("No command given");
			}
			// append_vector(command, vector<string>({"/usr/bin/ls", "-l", "-r"}));
			int ret = execute_command(rdfOutput, m_command, m_verbose);
			printf("ret=%d\n", ret);
		} else {
			if(!m_command.empty()) {
				throw runtime_error("Command should be empty");
			}
			replay_strace_logfile(rdfOutput, m_input_file, m_verbose);
		}
	}
};



class CommandCreator {
	int argc;
	const char ** argv;
	string input_file;
	string output_file;
	const char * processid = nullptr;
	size_t index ;
	bool verbose;
public:
	CommandCreator(int input_argc, const char ** input_argv)
	: argc(input_argc)
	, argv(input_argv) {
		/*
		First come some options, then the command.
		*/
		index = 1;
		verbose = false;
		for(; index < argc; ++index)
		{
			const char * arg = argv[index];
			if(0 == strcmp(arg, "-f")) {
				if( !input_file.empty()) {
					throw runtime_error("Input file should be given once only");
				}
				++index;
				if(index == argc) {
					throw runtime_error("No value for option -i");
				}
				if(processid != nullptr) {
					throw runtime_error("Pid should not be set when -i is set");
				}
				input_file = argv[index];
			}
			else if(0 == strcmp(arg, "-p")) {
				if(processid != nullptr) {
					throw runtime_error("Pid should be given once only");
				}
				++index;
				if(index == argc) {
					throw runtime_error("No value for option -p");
				}
				if(!input_file.empty()) {
					throw runtime_error("Input file should not be set when -p is set");
				}
				int tmp;
				if(1 != sscanf(argv[index], "%d", &tmp)) {
					throw runtime_error(string("Invalid pid:") + argv[index]);
				}
				processid = argv[index];
			}
			else if(0 == strcmp(arg, "-o")) {
				if(!output_file.empty()) {
					throw runtime_error("Output should be given once only");
				}
				++index;
				if(index == argc) {
					throw runtime_error("No value for option -p");
				}
				output_file = argv[index];
			}
			else if(0 == strcmp(arg, "-t")) {
				// Internal optional test.
				test_internal();
			}
			else if(0 == strcmp(arg, "-v")) {
				verbose = true;
			}
			else if(0 == strcmp(arg, "-h") || 0 == strcmp(arg, "-?")) {
				printf("%s <options> command ....\n", argv[0]);
				printf("    -f <input file>\n");
				printf("    -t              : test mode\n");
				printf("    -v              : verbose mode\n");
				printf("    -p <process id>\n");
				exit(EXIT_SUCCESS);
			}
			else {
				break;
			}
		}
	}
	
	CommandExecutor CreateExecutor() {
		if(! input_file.empty()) {
			if(processid != nullptr) {
				throw runtime_error("No pid should be given with an input file.");
			}
			if(index != argc) {
				throw runtime_error("No command should be given with an input file.");
			}
			return CommandExecutor(input_file, verbose);
		} else {
			vector<string> command = strace_command();
			if(processid == nullptr) {
				if(index == argc) {
					printf("No command and no pid. Nothing to do\n");
					exit(0);
				}
				for(; index < argc; ++index)
				{
					command.push_back(argv[index]);
				}
			} else {
				if(index != argc) {
					throw runtime_error("A command and a pid are given. Should be one or the other.\n");
				}
				append_vector(command, vector<string>({"-p", processid}));
			}
			return CommandExecutor(command, verbose);
		}
	}
	
	string output() const { return output_file; }
};


int main(int argc, const char ** argv)
{
	try {
		CommandCreator creator(argc, argv);
		CommandExecutor executor = creator.CreateExecutor();
		RdfOutput rdfOutput(creator.output());
		executor.Execute(rdfOutput);
	} catch(const exception & exc) {
		const char * bar = "********************************************************************************\n";
		fprintf(stderr, "%s", bar);
		fprintf(stderr, "Caught:%s\n", exc.what());
		fprintf(stderr, "%s", bar);
		exit(EXIT_FAILURE);
	}
	return 0;
}
