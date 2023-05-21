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
#include <numeric>

using namespace std;

template<class T>
static void append_vector(vector<string> & target, const T & source) {
	copy(source.begin(), source.end(), back_inserter(target));
}

enum CallState {INVALID, SIGNAL, PLAIN, UNFINISHED, RESUMED}; 

// Largest possible string offset.
static const size_t NOT_UNFINISHED = size_t(~0);

// This is for debugging only.
template<class Type>
string to_string(const vector<Type> &vec) {
	if(vec.empty()) {
		return "[]";
	}
	return "[" + accumulate(next(vec.begin()), vec.end(),
        vec[0],
        [](const Type& a, const Type & b) { return a + "#" + b;	}
	) + "]";
}

static string strip_quotes(const string &input_txt) {
	// Given strace syntax, the path name should be enclosed in double quotes.
	if((input_txt[0] != '"') || (input_txt[input_txt.size() - 1] != '"')) {
		throw runtime_error("String not enclosed:" + input_txt);
	}
	return input_txt.substr(1, input_txt.size() - 2);
}

static void replace_all(string& text, const string& from, const string& to)
{
    for (auto at = text.find(from, 0); at != std::string::npos;
        at = text.find(from, at + to.length()))
    {
        text.replace(at, from.length(), to);
    }
}

static string replace_all_copy(const string& text, const string& from, const string& to)
{
    auto copy = text;
    replace_all(copy, from, to);
    return copy;
}

static string escape_xml(const string &input_txt) {
	return replace_all_copy(input_txt, "/", "&#47;");
}

static ostream & logger() {
	return cerr;
}

/*
If this is a normal call, not unfinished, it returns NOT_UNFINISHED.
Otherwise, this returns the offset just after the end of the last argument,
that is, just before the marker string "<unfinished ...>" which must be at the end of the line.
*/
static size_t isUnfinished(const char * line) {
	static const char strUnfinished[] = "<unfinished ...>";
	const size_t len = strlen(line);

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
		throw runtime_error("isUnfinished inconsistency");
	}
	return end_offset;
}

/* These are the valid enclosing characters for the arguments of a system call, as dosplayed by strace.
This function is used to expect the proper enclosing char when the opening one is met. */
static char closing(char chr) {
	switch(chr) {
		case '(': return ')';
		case '{': return '}';
		case '[': return ']';
	}
	throw runtime_error(string("Invalid char:") + chr);
}

#define VERBOSE_WARNING 1
#define VERBOSE_LOG     2
#define VERBOSE_DEBUG   3
static int verbose_mode = 0;

static int global_created_pid = -1;

static vector<string> ArgumentsParser(const string & line, size_t start_offset, size_t end_offset, size_t & args_end) {
	if(verbose_mode >= VERBOSE_LOG) {
		logger() << "ArgumentsParser LINE=" << line << "\n";
	}
	if(verbose_mode >= VERBOSE_DEBUG) {
		logger() << "ArgumentsParser end_offset=" << end_offset << "\n";
		if(end_offset != NOT_UNFINISHED) {
			logger() << "ArgumentsParser line.substr(start_offset, end_offset-start_offset)=" << line.substr(start_offset, end_offset-start_offset) << "\n";
		}
	}

	bool in_quotes = false;
	int balance_parenthesis = 1;
	vector<string> args;
	string current_arg;
	bool still_running = true;
	bool escaped = false;
	stack<char> enclosers;
	enclosers.push(')');
	for(args_end = start_offset + 1; still_running && (args_end < end_offset); ++args_end) {
		const char chr = line[args_end];
		if(in_quotes) {
			// If in a string.
			switch(chr) {
				case '\\':
					if(escaped) {
						// TODO: It might be followed with a non-ascii char.
						current_arg += '\\';
						escaped = false;
					} else {
						escaped = true;
					}
					break;
				case '"':
					// strace might embed a double-quote in a string.
					if(escaped) {
						current_arg += '\\';
						escaped = false;
					} else {
						in_quotes = false;
					}
					current_arg += '"';
					break;
				default:
					if(escaped) {
						current_arg += '\\';
						escaped = false;
					}
					current_arg += chr;
					break;
			}
			continue;
		}
		switch(chr) {
			case ')': case '}': case ']':
				--balance_parenthesis;
				if(enclosers.top() != chr) {
					throw runtime_error(string("Should be closing characters:") + enclosers.top() + string(" instead of:") + chr
						+ string(" args_end=") + to_string(args_end) + string(" end_offset=") + to_string(end_offset));
				}
				enclosers.pop();
				if(balance_parenthesis == 0) {
					still_running = false;
				} else {
					current_arg += chr;
				}
				break;
			case '(': case '{': case '[':
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
					if(verbose_mode >= VERBOSE_DEBUG) {
						logger() << "\t" << "PUSH:" << current_arg << endl;
					}
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
	if(verbose_mode >= VERBOSE_DEBUG) {
		if(balance_parenthesis == 1) {
			logger() << "Unfinished" << endl;
		}
		logger() << "ArgumentsParser balance_parenthesis=" << balance_parenthesis << "\n";
		logger() << "ArgumentsParser end_offset=" << end_offset << "\n";
		logger() << "ArgumentsParser still_running=" << still_running << "\n";
		logger() << "\t" << "LAST:" << current_arg << endl;
	}
	if(!current_arg.empty()) {
		args.push_back(current_arg);
	}
	
	return args;
}

/*
This extracts the function name so the right parser can be created.
The line might start or not, with the pid.
19:58:35.830990 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3b1ca779d0) = 5557 <0.000185>
[pid  4233] 19:58:35.831382 close(3<pipe:[52233]>) = 0 <0.000016>
*/
class PreparsedLine {

	const char * ParseTimestamp(const char * time_start) {
		// It must point to a string like "19:58:35.834615"
		const char * time_end = strchr(time_start, ' ');
		if(time_end == nullptr) {
			throw std::runtime_error("No timestamp:" + string(time_start));
		}

		int hour, minutes;
		double seconds;
		int ret = sscanf(time_start, "%d:%d:%lf", &hour, &minutes, &seconds);
		if(ret != 3) {
			throw std::runtime_error(string(" Invalid time format:") + time_start);
		}
		startTime = hour * 24 * 3600 + minutes * 60 + seconds;
		return time_end;
	};
	
	void ParseReturn(const string & line, size_t args_end) {
		// Intialisation.
		call_return.clear();
		execution_time = 0.0;

		if(verbose_mode >= VERBOSE_DEBUG) {
			logger() << "args_end=" << args_end << " len=" << line.size() << ":" << line.substr(args_end) << endl;
		}
		/*
		It is not possible to detect the return value with the last "=" equal sign. Example:
		[pid 22560] 10:43:25.736857 poll([{fd=65<UDP:[54.36.162.150:38732->213.186.33.99:53]>, events=POLLIN}], 1, 4999) = 1 ([{fd=65, revents=POLLIN}]) <0.000009>
		TODO: This should be faster by using the len.
		*/
		if( args_end >= line.size() - 4) {
			return;
		}

		size_t offsetEqual = line.find('=', args_end);
		if(offsetEqual == string::npos) {
			throw runtime_error("Invalid end of arguments");
		}

		// Now, finds the execution time.
		size_t bracket_close = line.rfind('>');
		if(bracket_close == string::npos) {
			throw runtime_error("ParseReturn : No closing bracket for time.");
		}

		size_t bracket_open = line.rfind('<', bracket_close);
		if(bracket_open == string::npos) {
			throw runtime_error("ParseReturn : No opening bracket for time.");
		}
		if(1 != sscanf(line.c_str() + bracket_open, "<%lf>", &execution_time)) {
			throw runtime_error("ParseReturn : Cannot parse execution time.");
		}
		call_return = line.substr(offsetEqual + 1, bracket_open - offsetEqual - 1); // After "=" equal sign
	}

public:
	// Today's timestamp.
	double startTime = 0.0;
	double endTime = 0.0;
	string function_name;
	size_t args_offset = ~0; // Points to the open parenthesis after the function name.
	size_t unfinished_offset = ~0;
	int processid = -1; // -1 if this is the current process.
	CallState m_callstate = INVALID;
	vector<string> m_parsed_arguments;
	string call_return;
	double execution_time = 0.0;

	PreparsedLine() {}

	PreparsedLine(const string & line) {
		const char * line_start = line.c_str();
		static const char pid_prefix[] = "[pid ";
		int time_offset; // Beginning of the time-stamp.
		if(0 == strncmp(line_start, pid_prefix, sizeof(pid_prefix) - 1) ) {
			int pos_end;
			int ret_scan = sscanf(line_start + sizeof(pid_prefix) - 1, "%d] %n", &processid, &pos_end);
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
		if(verbose_mode >= VERBOSE_DEBUG) {
			logger() << "PROCESSID=" << processid << endl;
		}
		const char * time_end = ParseTimestamp(line_start + time_offset);

		static const char * function_valid_chars = "abcdefghijklmnopqrstuvwxyz0123456789_";
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
		
		unfinished_offset = isUnfinished(line.c_str());
		bool unfinished = unfinished_offset != NOT_UNFINISHED;

		const char str_resumed[] = " resumed>";
		bool resumed = nullptr != strstr(function_start, str_resumed);
		if(unfinished && resumed) {
			throw runtime_error("Cannot be unfinished and resumed");
		}
		if(resumed) {
			// The line is something like "[pid 22560] 10:43:33.601340 <... wait4 resumed> ) = 0 <0.000021>"
			m_callstate = RESUMED;
			if(is_valid_function) {
				throw runtime_error("Function name not be valid if resumed.");
			}
			// Extract function to be sure this is the right call.
			static const char str_dots[] = "<... ";
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

			// The first arguments of the call are in the "unfinished" line, maybe none of them.
			// The rest of these arguments - possibly none - comes in the "resumed" line.
			// The beginning of the arguments of the resumed call come after "resumed>".
			args_offset = function_end - line_start + sizeof(str_resumed) - 1;
		} else {
			m_callstate = unfinished ? UNFINISHED : PLAIN;
			if(!is_valid_function) {
				throw runtime_error(
					"Function name must be valid if unfinished or ok. longest_ascii=" + to_string(longest_ascii)
					+ "function_start=" + string(function_start));
			}
			args_offset = function_end - line_start;
		}
		function_name.assign(function_start, function_end);
		
		if(verbose_mode >= VERBOSE_WARNING) {
			switch(m_callstate) {
				case UNFINISHED:
					logger() << "UNFINISHED " << line << endl;
					break;
				case RESUMED:
					logger() << "RESUMED " << line << endl;
					break;
			}
		}

		if(verbose_mode >= VERBOSE_DEBUG) {
			logger() << "BEFORE ArgumentsParser: args_offset=" << args_offset << endl;
			logger() << "BEFORE ArgumentsParser: line + args_offset=" << (line.c_str() + args_offset) << endl;
		}
		size_t args_end;
		try {
			m_parsed_arguments = ArgumentsParser(line, args_offset, unfinished_offset, args_end);
		} catch(const exception & exc) {
			logger() << "Line=" << line << endl;
			throw;
		}
		if(!unfinished) {
			ParseReturn(line, args_end);
		}
	}
	
	// For debugging purpose only.
	friend ostream & operator<<(ostream & ostrm, const PreparsedLine & parsed) {
		ostrm << "function_name=" << parsed.function_name << endl;
		ostrm << "processid=" << parsed.processid << endl;
		ostrm << "m_parsed_arguments=" << to_string(parsed.m_parsed_arguments) << endl;
		return ostrm;
	}
};

/*******************************************************************************
**
** Internal tests.
**
*******************************************************************************/

static const struct {
	int pid;
	string function_name;
	string line;
} tests_preparsed[] = {
	{ -1, "clone", "19:58:35.830990 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3b1ca779d0) = 5557 <0.000185>"  },
	{ 4233, "close", "[pid  4233] 19:58:35.831382 close(3<pipe:[52233]>) = 0 <0.000016>"},
	{ 1338, "wait4", "[pid  1338] 14:54:00.613805 wait4(-1,  <unfinished ...>"},
	{ 22672, "open", "[pid 22672] 10:43:55.189420 open(\"/lib64/libnsssysinit.so\", O_RDONLY|O_CLOEXEC <unfinished ...>"},
	{ 22560, "connect", "[pid 22560] 10:43:33.601340 <... connect resumed> ) = 0 <0.000021>"},
	{ -1, "poll", "10:43:20.757752 <... poll resumed> )    = ? ERESTART_RESTARTBLOCK (Interrupted by signal) <0.009246>"},
	{ -1, "wait4", "10:07:39.571703 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 869 <0.307670>"},
};

/*
This extracts the beginning of a line displayed by strace. Notably, the pid is extracted.
*/
static void test_preparsed() {
	for(auto tst : tests_preparsed) {
		logger() << "PreparsedLine:" << tst.line << endl;
		PreparsedLine preparsed(tst.line);
		if(preparsed.processid != tst.pid) {
			throw runtime_error("Wrong pid:" + to_string(preparsed.processid) + " != " + to_string(tst.pid));
		}
		if(preparsed.function_name != tst.function_name) {
			throw runtime_error("Wrong function:" + preparsed.function_name);
		}
	}
	printf("Preparsed test end : OK.\n");
}


/* This contains typical lines displayed by strace. Each line represents a call to a system function.
Some calls are unfinished then resumed, possibly due to the reception of a signal.
In this case, two lines are displayed. The arguments might be split between the two lines.
The return value is at the end of the second line. */
static const struct {
	const string line;
	const int processid;
	const string function_name;
	const vector<string> m_parsed_arguments;
	const string call_return;
	const double execution_time;
} tests_preparsed2[] = {
	{ "19:58:35.830656 ioctl(0</dev/pts/2>, SNDCTL_TMR_STOP or TCSETSW, {B38400 opost isig icanon echo ...}) = 0 <0.000017>",
		-1,
		"ioctl",
		{"0</dev/pts/2>", " SNDCTL_TMR_STOP or TCSETSW", " {B38400 opost isig icanon echo ...}"},
		" 0 ", 0.000017
	},
	{ "[pid  5557] 19:58:35.833161 mmap(NULL, 124494, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0) = 0x7fb6a4518000 <0.000015>",
		5557,
		"mmap",
		{"NULL", " 124494", " PROT_READ", " MAP_PRIVATE", " 3</etc/ld.so.cache>", " 0"},
		" 0x7fb6a4518000 ", 0.000015
	},
	{ "[pid  5557] 19:58:35.833374 fstat(3</usr/lib64/libselinux.so.1>, {st_mode=S_IFREG|0755, st_size=142112, ...}) = 0 <0.000012>",
		5557,
		"fstat",
		{"3</usr/lib64/libselinux.so.1>", " {st_mode=S_IFREG|0755, st_size=142112, ...}"},
		" 0 ", 0.000012
	},
	{ "19:58:35.830990 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3b1ca779d0) = 5557 <0.000185>",
		-1,
		"clone",
		{"child_stack=0", " flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD", " child_tidptr=0x7f3b1ca779d0"},
		" 5557 ", 0.000185
	},
	{ "[pid  4233] 19:58:35.831382 close(3<pipe:[52233]>) = 0 <0.000016>",
		4233,
		"close",
		{"3<pipe:[52233]>"},
		" 0 ", 0.000016
	},
	{ "10:07:39.571703 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 869 <0.307670>",
		-1,
		"wait4",
		{"[{WIFEXITED(s) && WEXITSTATUS(s) == 0}]", " 0", " NULL"},
		" 869 ", 0.307670
	},
	{ "[pid 22672] 10:43:55.189420 open(\"/lib64/libnsssysinit.so\", O_RDONLY|O_CLOEXEC <unfinished ...>",
		22672,
		"open",
		{"\"/lib64/libnsssysinit.so\"", " O_RDONLY|O_CLOEXEC"},
		"", 0.0
	},
	{ "19:58:46.024321 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 5562 <5.318296>",
		-1,
		"wait4",
		{"[{WIFEXITED(s) && WEXITSTATUS(s) == 0}]", " WSTOPPED|WCONTINUED", " NULL"},
		" 5562 ", 5.318296
	},
	{ "[pid  4233] 19:58:40.705564 <... clone resumed> child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3b1ca779d0) = 5562 <0.000564>",
		4233,
		"clone",
		{"child_stack=0", " flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD", " child_tidptr=0x7f3b1ca779d0"},
		" 5562 ", 0.000564
	},
	{ "19:58:35.841846 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 5557 <0.010057>",
		-1,
		"wait4",
		{"[{WIFEXITED(s) && WEXITSTATUS(s) == 0}]", " WSTOPPED|WCONTINUED", " NULL"},
		" 5557 ", 0.010057
	},
	{ "[pid  1338] 14:54:00.613805 wait4(-1,  <unfinished ...>",
		1338,
		"wait4",
		{"-1"},
		"", 0.0
	},
	{ "[pid 22560] 10:43:33.601340 <... connect resumed> ) = 0 <0.000021>",
		22560,
		"connect",
		{},
		" 0 ", 0.000021
	},
	{ "10:43:20.757752 <... poll resumed> )    = ? ERESTART_RESTARTBLOCK (Interrupted by signal) <0.009246>",
		-1,
		"poll",
		{},
		" ? ERESTART_RESTARTBLOCK (Interrupted by signal) ", 0.009246
	},
	{ "22:58:47.412832 read(7</usr/libpcre2-8.so.0.9.0>, \"ABC\", 832) = 832 <0.000031>",
		-1,
		"read",
		{"7</usr/libpcre2-8.so.0.9.0>", " \"ABC\"", " 832"},
		" 832 ", 0.000031
	},
	{ R"(22:58:47.412832 read(7</usr/libpcre2-8.so.0.9.0>, "\177ELF\340\"\0\0\222\2@T\18\4\1&", 832) = 832 <0.000031>)",
		-1,
		"read",
		{"7</usr/libpcre2-8.so.0.9.0>", R"( "\177ELF\340\"\0\0\222\2@T\18\4\1&")", " 832"},
		" 832 ", 0.000031
	},
	{ R"(00:23:29.461586 execve("/usr/bin/ls", ["ls"], 0x7fffde63bf28 /* 18 vars */) = 0 <0.003298>)",
		-1,
		"execve",
		{"\"/usr/bin/ls\"", " [\"ls\"]", " 0x7fffde63bf28 /* 18 vars */"},
		" 0 ", 0.003298
	},
	{ R"(00:23:29.461586 execve("/usr/bin/ls", ["ls", "-l"], 0x7fffde63bf28 /* 18 vars */) = 0 <0.003298>)",
		-1,
		"execve",
		{"\"/usr/bin/ls\"", " [\"ls\", \"-l\"]", " 0x7fffde63bf28 /* 18 vars */"},
		" 0 ", 0.003298
	},
	{ R"([pid 22568] 10:43:27.981223 recvmsg(51<UNIX:[15588905->15588906]>,  <unfinished ...>)",
		22568,
		"recvmsg",
		{"51<UNIX:[15588905->15588906]>"},
		"", 0.0
	},
	{ R"([pid 22568] 10:43:27.993342 close(49<UNIX:[15589437->15589436]>) = 0 <0.000006>)",
		22568,
		"close",
		{"49<UNIX:[15589437->15589436]>"},
		" 0 ", 0.000006
	},
	{ R"([pid 22526] 10:43:25.744972 recvfrom(34<TCP:[54.36.162.150:59830->92.122.122.138:80]>, 0x7f7794efc9e7, 1, MSG_PEEK, NULL, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.000012>)",
		22526,
		"recvfrom",
		{"34<TCP:[54.36.162.150:59830->92.122.122.138:80]>", " 0x7f7794efc9e7", " 1", " MSG_PEEK", " NULL", " NULL"},
		" -1 EAGAIN (Resource temporarily unavailable) ", 0.000012
	},
	{ R"([pid 22526] 10:43:25.744679 recvfrom(34<TCP:[54.36.162.150:59830->92.122.122.138:80]>, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nLast-Modified: Mon, 15 May 2017 18:04:40 GMT\r\nETag: \"ae780585f49b94ce1444eb7d28906123\"\r\nAccept-Ranges: bytes\r\nServer: AmazonS3\r\nX-Amz-Cf-I"..., 32768, 0, NULL, NULL) = 384 <0.000012>)",
		22526,
		"recvfrom",
		{"34<TCP:[54.36.162.150:59830->92.122.122.138:80]>", R"( "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nLast-Modified: Mon, 15 May 2017 18:04:40 GMT\r\nETag: \"ae780585f49b94ce1444eb7d28906123\"\r\nAccept-Ranges: bytes\r\nServer: AmazonS3\r\nX-Amz-Cf-I"...)", " 32768", " 0", " NULL", " NULL"},
		" 384 ", 0.000012
	},
	{ R"([pid 22526] 10:43:25.737922 poll([{fd=20<pipe:[15588425]>, events=POLLIN|POLLPRI}, {fd=34<TCP:[54.36.162.150:59830->92.122.122.138:80]>, events=POLLIN|POLLPRI}], 2, -1 <unfinished ...>)",
		22526,
		"poll",
		{"[{fd=20<pipe:[15588425]>, events=POLLIN|POLLPRI}, {fd=34<TCP:[54.36.162.150:59830->92.122.122.138:80]>, events=POLLIN|POLLPRI}]", " 2", " -1"},
		"", 0.0
	},
	{ R"([pid 22526] 10:43:25.737840 sendto(34<TCP:[54.36.162.150:59830->92.122.122.138:80]>, "GET /success.txt HTTP/1.1\r\nHost: detectportal.firefox.com\r\nUser-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\nAccep"..., 296, 0, NULL, 0) = 296 <0.000033>)",
		22526,
		"sendto",
		{"34<TCP:[54.36.162.150:59830->92.122.122.138:80]>", R"( "GET /success.txt HTTP/1.1\r\nHost: detectportal.firefox.com\r\nUser-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\nAccep"...)", " 296", " 0", " NULL", " 0"},
		" 296 ", 0.000033
	},
	{ R"([pid 22560] 10:43:25.736857 poll([{fd=65<UDP:[54.36.162.150:38732->213.186.33.99:53]>, events=POLLIN}], 1, 4999) = 1 ([{fd=65, revents=POLLIN}]) <0.000009>)",
		22560,
		"poll",
		{"[{fd=65<UDP:[54.36.162.150:38732->213.186.33.99:53]>, events=POLLIN}]", " 1", " 4999"},
		" 1 ([{fd=65, revents=POLLIN}]) ", 0.000009
	},
};

/*
This extracts the beginning of a line displayed by strace. Notably, the pid is extracted.
TODO: Test merge.
*/
static void test_preparsed2() {
	for(auto tst : tests_preparsed2) {
		logger() << "=================================================================" << endl;
		logger() << "PreparsedLine:" << tst.line << endl;
		PreparsedLine preparsed(tst.line);
		if(preparsed.processid != tst.processid) {
			throw runtime_error("Wrong pid:" + to_string(preparsed.processid) + " != " + to_string(tst.processid));
		}
		if(preparsed.function_name != tst.function_name) {
			throw runtime_error("Wrong function:" + preparsed.function_name + "!=" + tst.function_name);
		}
		if(preparsed.m_parsed_arguments != tst.m_parsed_arguments) {
			logger() << "ACTUAL:" << preparsed.m_parsed_arguments.size() << endl;
			logger() << "EXPECT:" << tst.m_parsed_arguments.size() << endl;
			logger() << "ACTUAL:" << to_string(preparsed.m_parsed_arguments) << endl;
			logger() << "EXPECT:" << to_string(tst.m_parsed_arguments) << endl;
			throw runtime_error("Wrong arguments:" + to_string(preparsed.m_parsed_arguments) + "!=" + to_string(tst.m_parsed_arguments));
		}
		if(preparsed.call_return != tst.call_return) {
			throw runtime_error("Wrong return:[" + preparsed.call_return + "]!=[" + tst.call_return + "]");
		}
		if(preparsed.execution_time != tst.execution_time) {
			throw runtime_error("Wrong execution time:[" + to_string(preparsed.execution_time) + "]!=[" + to_string(tst.execution_time) + "]");
		}
	}
	printf("Preparsed test end : OK.\n");
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
	{ NOT_UNFINISHED, "close(4<pipe:[52233]> < unfinished ...>"},
	{ NOT_UNFINISHED, "<unfinished ...> "},
	{ NOT_UNFINISHED, "<unfinished>"},
	{ NOT_UNFINISHED, "abc"},
};

/* This tests the detection of the end of thearguments, and if the call is unfinished. */
static void test_unfinished() {
	for(auto tst : tests_unfinished) {
		size_t ret = isUnfinished(tst.line);
		logger() << "TST:" << tst.line << " Expected=" << tst.unfinished << " Actual=" << ret << endl;
		if(tst.unfinished == ret && ret != NOT_UNFINISHED) {
			logger() << "[" << string(tst.line, tst.line + ret) << "]" << endl;
		}
		if( ret != tst.unfinished) {
			throw runtime_error(string("Wrong unfinished value:") + tst.line);
		}
	}
	printf("Unfinished detection test end : OK.\n");
}

struct test_def_parsing_args {
	const char * input;
	const vector<const char *> outputs;
	const char * call_return;
	const size_t m_args_end;
	
	void test() {
		logger() << "Input=" << input << endl;
		size_t args_end;
		vector<string> args = ArgumentsParser(input, 0, NOT_UNFINISHED, args_end);
		copy(outputs.begin(), outputs.end(), ostream_iterator<const char *>(logger(), "+"));
		logger() << endl;
		copy(args.begin(), args.end(), ostream_iterator<const string &>(logger(), "+"));
		logger() << endl;
		
		if(args.size() != outputs.size() ) {
			throw runtime_error("Different sizes");
		}
		for(size_t index = 0; index < outputs.size(); ++index) {
			if( args[index] != outputs[index]) {
				throw runtime_error("Different args");
			}
		}
		if(args_end != m_args_end ) {
			throw runtime_error("Different args end:" + to_string(args_end) + " should be " + to_string(m_args_end));
		}
	}
};
static const test_def_parsing_args test_args_parsing[] = {
	{"(xyz)",
		{"xyz"},
		"",
		5},
	{"(x,y,z)",
		{"x", "y", "z"},
		"",
		7},
	{"(x,\"y\",z)",
		{"x", "\"y\"", "z"},
		"",
		9},
	{"(x,(y),z)",
		{"x", "(y)", "z"},
		"",
		9},
	{"(x,(y1,y2),z)",
		{"x", "(y1,y2)", "z"},
		"",
		13},
	{"(7</usr/share>, {st_mode=S_IFREG|0644, st_size=3678, ...}) = 0 <0.000059>",
		{"7</usr/share>", " {st_mode=S_IFREG|0644, st_size=3678, ...}"},
		" 0 <0.000059>",
		58},
	{"(AT_FDCWD, \"/usr/coreutils.moz\", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000031>",
		{"AT_FDCWD", " \"/usr/coreutils.moz\"", " O_RDONLY"},
		" -1 ENOENT (No such file or directory) <0.000031>",
		42},
};

static void test_parsing() {
	printf("Internal test start.\n");
	for(auto one_test : test_args_parsing) {
		one_test.test();
	}
	printf("Parsing test end : OK.\n");
}

static void test_internal() {
	test_unfinished();
	test_preparsed();
	test_preparsed2();
	test_parsing();
	printf("Internal test end : OK.\n");
}

/*******************************************************************************
**
** Writing triples.
**
*******************************************************************************/

static const string survolUrl = "http://www.primhillcomputers.com/survol";

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
		
		*m_ostream << R"(<?xml version="1.0" encoding="UTF-8"?>)"                     << endl;
		*m_ostream << R"(<rdf:RDF)"                                                   << endl;
		*m_ostream << R"(   xmlns:xsd="http://www.w3.org/2001/XMLSchema#")"           << endl;
		*m_ostream << R"(   xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#")" << endl;
		*m_ostream << R"(   xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#")"      << endl;
		*m_ostream << R"(   xmlns:survol=")" << survolUrl << R"(#")"                  << endl;
		*m_ostream << R"(>)"                                                          << endl;
	}

	~RdfOutput() {
		*m_ostream << "</rdf:RDF>" << endl;
		if(m_must_close) {
			m_ofstream.close();
		}
		printf("Closed RdfOutput\n");
	}

	void WriteLine(const string &outputLine) {
		*m_ostream << outputLine << endl;
	}
};

/*******************************************************************************
**
** Handling created CIM object.
**
*******************************************************************************/
class CIMObjectManager {
	typedef map<string, string> KeyToMoniker;
	static map<string, KeyToMoniker> mapClassValueMoniker;

	static string CreateMonikerNoCache(const string & className, const string &key, const string & value) {
		return survolUrl + "#" + className + "." + key + "=" + value;
	}
public:
	/* This works only for CIM classes which have a single key, which is by far the most common case. */
	static string CreateMoniker(const string & className, const string &key, const string & value) {
		auto pairClassIter = mapClassValueMoniker.insert(pair(className, KeyToMoniker()));

		KeyToMoniker & mapKeyToMoniker = pairClassIter.first->second;
		auto pairObjectIter = mapKeyToMoniker.insert(pair(key, string()));
		if(pairObjectIter.second) {
			pairObjectIter.first->second = CreateMonikerNoCache(className, key, value);
		}
		return pairObjectIter.first->second;
	}

	void DumpToRDF() {}
};
map<string, CIMObjectManager::KeyToMoniker> CIMObjectManager::mapClassValueMoniker;

struct CIMClassManager {
	static map<string, string> mapClassMoniker;

	static string CreateMonikerNoCache(const string & className) {
		return survolUrl + "#" + className;
	}
public:
	static string CreateMoniker(const string & className) {
		auto pairClassIter = mapClassMoniker.insert(pair(className, string()));
		if(pairClassIter.second) {
			pairClassIter.first->second = CreateMonikerNoCache(className);
		}
		return pairClassIter.first->second;
	}

	void DumpToRDF() {}
};
map<string, string> CIMClassManager::mapClassMoniker;

/*******************************************************************************
**
** Types of arguments of system calls.
**
    <ns1:Category>Others</ns1:Category>
    <rdf:type rdf:resource="http://www.primhillcomputers.com/survol#CIM_DataFile"/>
    <ns1:Name>C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/./UnitTests/mineit_find_grep.strace.docker/home</ns1:Name>
    <ns1:FileName>home</ns1:FileName>
	
	
  <rdf:Description rdf:about="http://vps516494.ovh.net:80/Survol/survol/entity.py?xid=CIM_Process.Handle=1237">
    <rdf:type rdf:resource="http://www.primhillcomputers.com/survol#CIM_Process"/>
    <ldt:pid>1237</ldt:pid>
    <rdfs:label>oracle</rdfs:label>
    <ldt:LMI_Account>oracle</ldt:LMI_Account>
    <ldt:Handle>1237</ldt:Handle>
    <ldt:ppid rdf:resource="http://vps516494.ovh.net:80/Survol/survol/entity.py?xid=CIM_Process.Handle=1"/>
  </rdf:Description>
  
  <rdf:Description rdf:about=
"http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_DataFile.Name=C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/./UnitTests/mineit_find_grep.strace.docker/home">
    <ns1:Category>Others</ns1:Category>
    <rdf:type rdf:resource="http://www.primhillcomputers.com/survol#CIM_DataFile"/>
    <ns1:Name>C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/./UnitTests/mineit_find_grep.strace.docker/home</ns1:Name>
    <ns1:FileName>home</ns1:FileName>
  </rdf:Description>

*******************************************************************************/



// <rdf:type rdf:resource="http://www.primhillcomputers.com/survol#CIM_DataFile"/>
// <ldt:ppid rdf:resource="http://vps516494.ovh.net:80/Survol/survol/entity.py?xid=CIM_Process.Handle=1"/>
static string tag_resource(const string & rdfNamespace, const string & property, const string &moniker) {
	return "<" + rdfNamespace + ":" + property + " rdf:resource=\"" + moniker + "\"/>";
}

static string tag_write(const string & property, const string & input_txt, const string & rdfNamespace = "survol") {
	const string escaped_txt = escape_xml(input_txt);
	const string tag_open = "<" + rdfNamespace + ":" + property + ">";
	const string tag_close = "</" + rdfNamespace + ":" + property + ">";
	return tag_open + escaped_txt + tag_close;
}

struct ArgumentType {
	// FIXME : property is never used.
	virtual string ToRdf(const string & property, const string & input_txt) const = 0;
};

template<class DerivedArgument>
struct ArgumentTypeWrapper : public ArgumentType {
	static constexpr const DerivedArgument ArgSingleton = DerivedArgument{};
};

struct SystemCallArgument_ProcessId : public ArgumentTypeWrapper<SystemCallArgument_ProcessId> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return tag_write(property, input_txt);
	}
};
struct SystemCallArgument_IntPtr : public ArgumentTypeWrapper<SystemCallArgument_IntPtr> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return tag_write(property, input_txt);
	}
};
struct SystemCallArgument_Int : public ArgumentTypeWrapper<SystemCallArgument_Int> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return tag_write(property, input_txt);
	}
};
struct SystemCallArgument_RusagePtr : public ArgumentTypeWrapper<SystemCallArgument_RusagePtr> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return tag_write(property, input_txt);
	}
};
struct SystemCallArgument_Fd : public ArgumentTypeWrapper<SystemCallArgument_Fd> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return tag_write(property, input_txt);
	}
};
struct SystemCallArgument_Addr : public ArgumentTypeWrapper<SystemCallArgument_Addr> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return tag_write(property, input_txt);
	}
};
struct SystemCallArgument_AddrLen : public ArgumentTypeWrapper<SystemCallArgument_AddrLen> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return tag_write(property, input_txt);
	}
};
struct SystemCallArgument_PathName : public ArgumentTypeWrapper<SystemCallArgument_PathName> {
	string ToRdf(const string & property, const string & input_txt) const override {
		string path_name = strip_quotes(input_txt);
		string moniker = CIMObjectManager::CreateMoniker("CIM_DataFile", "Name", path_name);
		return tag_resource("survol", property, moniker);
	}
};
struct SystemCallArgument_Directory : public ArgumentTypeWrapper<SystemCallArgument_Directory> {
	string ToRdf(const string & property, const string & input_txt) const override {
		string path_name = strip_quotes(input_txt);
		string moniker = CIMObjectManager::CreateMoniker("CIM_Directory", "Name", path_name);
		return tag_resource("survol", property, moniker);
	}
};
struct SystemCallArgument_Process : public ArgumentTypeWrapper<SystemCallArgument_Process> {
	string ToRdf(const string & property, const string & pid) const override {
		string moniker = CIMObjectManager::CreateMoniker("CIM_Process", "Handle", pid);
		return tag_resource("survol", property, moniker);
	}
};
struct SystemCallArgument_Class : public ArgumentTypeWrapper<SystemCallArgument_Class> {
	string ToRdf(const string & property, const string & className) const override {
		string moniker = CIMClassManager::CreateMoniker(className);
		return tag_resource("rdf", property, moniker);
	}
};
struct SystemCallArgument_ArgV : public ArgumentTypeWrapper<SystemCallArgument_ArgV> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return tag_write(property, input_txt);
	}
};
struct SystemCallArgument_EnvP : public ArgumentTypeWrapper<SystemCallArgument_EnvP> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return tag_write(property, input_txt);
	}
};
struct SystemCallArgument_Flags : public ArgumentTypeWrapper<SystemCallArgument_Flags> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return tag_write(property, input_txt);
	}
};
struct SystemCallArgument_Mode : public ArgumentTypeWrapper<SystemCallArgument_Mode> {
	string ToRdf(const string & property, const string & input_txt) const override {
		return tag_write(property, input_txt);
	}
};


/*******************************************************************************
**
** Writing to RDF.
**
*******************************************************************************/

typedef pair<const char *, const ArgumentType &> NamedArgument;
typedef initializer_list< NamedArgument > FunctionSignature;

/*
Objects modelling system calls are written as soon as they are parsed from strace output.
It would be possible to store them in a triple-store and dump the triples at the end,
but it would require more plumbing and storing internal data.
*/
class ObjectStart {
	RdfOutput & rm_dfOutput;
public:
	ObjectStart(RdfOutput & rdfOutput, const string &func, const string & start_time, const string & end_time)
	: rm_dfOutput(rdfOutput) {
		static size_t calls_counter = 0;
		string callMoniker = CIMObjectManager::CreateMoniker(func, "CallId", to_string(calls_counter));
		++calls_counter;
		rm_dfOutput.WriteLine("<rdf:Description about=\"" + callMoniker + "\">");
	}
	
	void AddSpecialKeyValue(const string & rdfNamespace , const string & key, const string & value) {
		string rdfKeyValue = tag_write(key, value, rdfNamespace);
		rm_dfOutput.WriteLine("    " + rdfKeyValue);
	}
	
	void AddSurvolKeyValue(const NamedArgument & oneArg, const string & value) {
		if(verbose_mode >= VERBOSE_DEBUG) {
			logger() << "First / Value=" << oneArg.first << " " << value << endl;
		}
		string trimedValue = value;
		trimedValue.erase(0, trimedValue.find_first_not_of("\t\n\v\f\r ")); // left trim
		trimedValue.erase(trimedValue.find_last_not_of("\t\n\v\f\r ") + 1); // right trim
		const string & rdfOut = oneArg.second.ToRdf(oneArg.first, trimedValue);
		rm_dfOutput.WriteLine("    " + rdfOut);
	}
	
	~ObjectStart() {
		rm_dfOutput.WriteLine("</rdf:Description>");
	}
};


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
	double startTime;
	double execution_time;
	int processid;
public:
	STraceCall(const string & line, const PreparsedLine & preparsedLine)
	: parsed_arguments(preparsedLine.m_parsed_arguments)
	, startTime(preparsedLine.startTime)
	, processid(preparsedLine.processid)
	, execution_time(preparsedLine.execution_time) {
	}
	
	virtual const char * function() const = 0;
	virtual const FunctionSignature & Signature() const  = 0;

	// Some system calls have optional arguments.
	virtual size_t MinimumArgumentsNumber() const {
		return Signature().size();
	}

	static string FormatTime(double seconds) {
		if(seconds == 0) {
			return "00:00:00.000000";
		}
		char buffer[32];
		int int_seconds = (int)seconds;
		int micro_seconds = (int)((seconds - int_seconds) * 1000000);
		// The result is something like: "2018-04-09T10:00:00"^^xsd:dateTime
		sprintf(buffer, "\"%02d:%02d:%02d.%06d\"^^xsd:dateTime", (int_seconds / 3600) % 24, (int_seconds / 60) % 60, int_seconds % 60, micro_seconds);
		return buffer;
	}
	
	string StartTime() const {
		return FormatTime(startTime);
	}

	string EndTime() const {
		// TODO: What if it finishes on the next day ? This is a corner case.
		return FormatTime(startTime + execution_time);
	}
	
	
	/*
  <rdf:Description rdf:about=
"http://rchateau-hp:80/LocalExecution/entity.py?xid=CIM_DataFile.Name=C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/./UnitTests/mineit_find_grep.strace.docker/home">
    <ns1:Category>Others</ns1:Category>
    <rdf:type rdf:resource="http://www.primhillcomputers.com/survol#CIM_DataFile"/>
    <ns1:Name>C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/./UnitTests/mineit_find_grep.strace.docker/home</ns1:Name>
    <ns1:FileName>home</ns1:FileName>
  </rdf:Description>
	*/
	virtual void WriteCall(RdfOutput & rdfOutput) {
		const FunctionSignature & argsDefs = Signature();
		if(parsed_arguments.size() > argsDefs.size()) {
			throw runtime_error("Too many arguments when writing");
		}

		size_t minArgs = MinimumArgumentsNumber();
		if(verbose_mode >= VERBOSE_DEBUG) {
			logger() << "Signature=" << argsDefs.size() << " Minimum=" << minArgs << endl;
		}
		ObjectStart objectStart(rdfOutput, function(), StartTime(), EndTime());

		objectStart.AddSpecialKeyValue("schema", "StartTime", StartTime());
		objectStart.AddSpecialKeyValue("schema", "EndTime", EndTime());

		// objectStart.AddSpecialKeyValue("rdf", "type", "SystemCall");
		static const constexpr NamedArgument typePseudoArg{ "type", SystemCallArgument_Class::ArgSingleton };
		// TODO: Declare the class "function" as a subclass of "SystemCall".
		objectStart.AddSurvolKeyValue(typePseudoArg, function());

		static const constexpr NamedArgument pidPseudoArg{ "CallingProcess", SystemCallArgument_Process::ArgSingleton };
		
		int effective_pid = processid == -1 ? global_created_pid : processid;
		objectStart.AddSurvolKeyValue(pidPseudoArg, to_string(effective_pid));

		size_t index = 0;
		for(const auto & oneArg : argsDefs) {
			if(index >= parsed_arguments.size()) {
				if(index >= minArgs) {
					break;
				} else {
					throw runtime_error(string("Not enough arguments for:") + oneArg.first);
				}
			}
			string value = parsed_arguments[index];
			objectStart.AddSurvolKeyValue(oneArg, value);
			++index;
		}
	}
	
	friend ostream & operator<<(ostream & ostrm, const STraceCall & traceCall) {
		ostrm << to_string(traceCall.parsed_arguments) << endl;
		return ostrm;
	}

	// Debugging only.
	void Display() const {
		for(const string & arg: parsed_arguments) {
			logger() << "\t" << arg << endl;
		}
	}

	void MergeWithResumed(const PreparsedLine & resumed) {
		if(verbose_mode >= VERBOSE_DEBUG) {
			logger() << "MERGING " << function() << endl;
		}
		if(resumed.function_name != function()) {
			throw runtime_error(string("Cannot merge ") + function() + " with " + resumed.function_name);
		}
		parsed_arguments.insert(parsed_arguments.end(), resumed.m_parsed_arguments.begin(), resumed.m_parsed_arguments.end());
		if(parsed_arguments.size() < MinimumArgumentsNumber()) {
			logger() << "Parsed" << endl;
			logger() << *this << endl;
			logger() << "Resumed" << endl;
			logger() << resumed << endl;
			throw runtime_error("Not enough arguments after merging.");
		}
		if(parsed_arguments.size() > Signature().size()) {
			throw runtime_error("Too many arguments after merging");
		}
		if(execution_time != 0.0) {
			throw runtime_error("Execution time of unfinished call must be 0.");
		}
		execution_time = resumed.execution_time;
		if(verbose_mode >= VERBOSE_DEBUG) {
			logger() << "MERGED " << function() << " OK" << endl;
		}
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
			{ "sockfd",  SystemCallArgument_Fd::ArgSingleton },
			{ "addr",    SystemCallArgument_Addr::ArgSingleton },
			{ "addrlen", SystemCallArgument_AddrLen::ArgSingleton },
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
			{ "pathname", SystemCallArgument_PathName::ArgSingleton },
			{ "argv",     SystemCallArgument_ArgV::ArgSingleton },
			{ "envp",     SystemCallArgument_EnvP::ArgSingleton },
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
			{ "fildes", SystemCallArgument_Fd::ArgSingleton },
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
			// FIXME : And what about directories ?
			{ "pathname", SystemCallArgument_PathName::ArgSingleton },
			{ "flags",    SystemCallArgument_Flags::ArgSingleton },
			{ "mode",     SystemCallArgument_Mode::ArgSingleton },
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
			{ "fd", SystemCallArgument_Fd::ArgSingleton },
			{ "pathname", SystemCallArgument_PathName::ArgSingleton },
			{ "oflag",    SystemCallArgument_Flags::ArgSingleton },
			{ "mode",     SystemCallArgument_Mode::ArgSingleton },
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
			{ "pid", SystemCallArgument_ProcessId::ArgSingleton },
			{ "wstatus", SystemCallArgument_IntPtr::ArgSingleton },
			{ "options", SystemCallArgument_Int::ArgSingleton },
			{ "rusage",  SystemCallArgument_RusagePtr::ArgSingleton },
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
map<string, STraceFactory::Generator> dictCalls = {
	{"accept",            nullptr },
	{"arch_prctl",        nullptr },
	{"bind",              nullptr },
	{"brk",               nullptr },
	{"clone",             nullptr },
	{"close",             nullptr },
	{"connect",           GenerTmpl<STraceCall_connect> },
	{"dup",               nullptr },
	{"dup2",              nullptr },
	{"dup3",              nullptr },
	{"epoll_create1",     nullptr },
	{"epoll_ctl",         nullptr },
	{"epoll_wait",        nullptr },
	{"eventfd2",          nullptr },
	{"execve",            GenerTmpl<STraceCall_execve> },
	{"exit",              nullptr },
	{"exit_group",        nullptr },
	{"faccessat",         nullptr },
	{"fadvise64",         nullptr },
	{"fallocate",         nullptr },
	{"fchdir",            GenerTmpl<STraceCall_fchdir> },
	{"fchmod",            nullptr },
	{"fchown",            nullptr },
	{"fcntl",             nullptr },
	{"fstat",             nullptr },
	{"fstatfs",           nullptr },
	{"fsync",             nullptr },
	{"ftruncate",         nullptr },
	{"getdents",          nullptr },
	{"getdents64",        nullptr },
	{"getpeername",       nullptr },
	{"getsockname",       nullptr },
	{"getsockopt",        nullptr },
	{"inotify_add_watch", nullptr },
	{"inotify_init1",     nullptr },
	{"ioctl",             nullptr },
	{"listen",            nullptr },
	{"lseek",             nullptr },
	{"madvise",           nullptr },
	{"mlock",             nullptr },
	{"mmap",              nullptr },
	{"mprotect",          nullptr },
	{"munmap",            nullptr },
	{"newfstatat",        nullptr },
	{"open",              GenerTmpl<STraceCall_open> },
	{"openat",            GenerTmpl<STraceCall_openat> },
	{"pipe",              nullptr },
	{"pipe2",             nullptr },
	{"poll",              nullptr },
	{"ppoll",             nullptr },
	{"pread64",           nullptr },
	{"pselect6",          nullptr },
	{"pwrite64",          nullptr },
	{"read",              nullptr },
	{"readahead",         nullptr },
	{"recvfrom",          nullptr },
	{"recvmsg",           nullptr },
	{"shmat",             nullptr },
	{"shmdt",             nullptr },
	{"shmget",            nullptr },
	{"shutdown",          nullptr },
	{"select",            nullptr },
	{"sendmmsg",          nullptr },
	{"sendmsg",           nullptr },
	{"sendto",            nullptr },
	{"setsockopt",        nullptr },
	{"socket",            nullptr },
	{"socketpair",        nullptr },
	{"unshare",           nullptr },
	{"vfork",             nullptr },
	{"wait4",             GenerTmpl<STraceCall_wait4> },
	{"write",             nullptr },
	{"writev",            nullptr },
};

static map<int, shared_ptr<STraceCall>> unfinished_calls;


static shared_ptr<STraceCall> GenerateCallFromParsed(const PreparsedLine & preparsedLine, const string & line) {
	auto iter = dictCalls.find(preparsedLine.function_name);
	if(iter == dictCalls.end()) {
		throw runtime_error("Cannot find function:" + preparsedLine.function_name);
	}
	STraceFactory::Generator gener = iter->second;
	if(gener == nullptr) {
		return shared_ptr<STraceCall>();
	}
	return gener(line, preparsedLine);
}


shared_ptr<STraceCall> STraceFactory::factory(const string & line) {
	PreparsedLine preparsedLine(line);
	switch(preparsedLine.m_callstate) {
		case UNFINISHED: {
			shared_ptr<STraceCall> ptrUnfinished = GenerateCallFromParsed(preparsedLine, line);
			if(!ptrUnfinished) {
				if(verbose_mode >= VERBOSE_DEBUG) {
					logger() << "Cannot create call object with:" << preparsedLine.function_name << endl;
				}
				return shared_ptr<STraceCall>();
			}
			if(preparsedLine.function_name != ptrUnfinished->function()) {
				throw runtime_error("Inconsistency creating call object");
			}

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
				// Usual case: The call is resumed in the pid where it was unfinished.
				resuming_pid = preparsedLine.processid;
			}

			// There should not be another unfinished call for this pid.
			auto itr_pair = unfinished_calls.insert(make_pair(resuming_pid, ptrUnfinished));
			if(!itr_pair.second) {
				throw runtime_error("Unfinished call " + string(itr_pair.first->second->function()) + " present for pid="
					+ to_string(resuming_pid) + " when inserting " + string(ptrUnfinished->function()) + "/" + preparsedLine.function_name);
			}

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

static size_t processed_lines = 0;

static void process_line(RdfOutput & rdfOutput, const string &line) {
	++processed_lines;
	if(verbose_mode >= VERBOSE_LOG) {
		logger() << processed_lines << "\t" << line << endl;
	}
	try {
		shared_ptr<STraceCall> ptr = STraceFactory::factory(line);
		if(ptr.get() == nullptr) {
			return;
		}
		if(verbose_mode >= VERBOSE_DEBUG) {
			logger() << "Function=" << ptr->function() << endl;
			ptr->Display();
		}
		ptr->WriteCall(rdfOutput);
	} catch( const std::exception & exc) {
		cerr << "Line:" << processed_lines << ". Caught:" <<  exc.what() << endl;
		cerr << "RET=" << line << endl;
	}
}

/*******************************************************************************
**
** Definition of system calls as classes.
**
*******************************************************************************/
static void DefineSystemCallsClasses(RdfOutput & rdfOutput)
{
	/*
	Might as well iterate on keys of CIMClassManager which are in dictCalls.
	*/
	const string baseClassMoniker = CIMClassManager::CreateMoniker("SystemCall");
	for(auto iter : dictCalls) {
		if(iter.second == nullptr) {
			continue;
		}
		const string classMoniker = CIMClassManager::CreateMoniker(iter.first);
		//add base class
		//alsdjhflaksjdfha
	}
}

static void DefineCIMClasses(RdfOutput & rdfOutput)
{
	/*
	Might as well iterate on keys of CIMClassManager which are not in dictCalls.
	*/
	static const string classesList[] = {
		"CIM_Process",
		"CIM_DataFile",
		"CIM_Directory"};
		
	//s;ldkjf;alskdj
}

/*******************************************************************************
**
** Execution of strace in a subprocess.
**
*******************************************************************************/

static vector<string> strace_command() {
	/*
	# Run tracer process as a detached grandchild, not as parent of the tracee. This reduces the visible
	# effect of strace by keeping the tracee a direct child of the calling process.
	# On WSL, it might fail with the error:
	# strace: Could not attach to process. If your uid matches the uid of the target process,
	# check the setting of /proc/sys/kernel/yama/ptrace_scope, or try again as the root user.
	# For more details, see /etc/sysctl.d/10-ptrace.conf: Operation not permitted
	# strace: attach: ptrace(PTRACE_ATTACH, 498): Operation not permitted
            ### trace_command += ["-D"]
	*/

	vector<string> command{"/usr/bin/strace", "-q", "-qq", "-f", "-tt", "-T", "-s", "10000"};
	const bool is_deprecated = false;
	const vector<string> dependent_options{is_deprecated
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

static int popen3(RdfOutput & rdfOutput, int fd[3], char * const * cmd) {
    int i, e;
    int p[3][2];
    // set all the FDs to invalid
    for(i=0; i<3; i++)
        p[i][0] = p[i][1] = -1;
    // create the pipes
    for(int i=0; i<3; i++)
        if(pipe(p[i]))
            return -1;
    // and fork
    global_created_pid = fork();
    if(-1 == global_created_pid)
        return -1;
    // in the parent?
    if(global_created_pid) {
        close(p[STDIN_FILENO][0]);
        close(p[STDOUT_FILENO][1]);

        fd[STDERR_FILENO] = p[STDERR_FILENO][0];
        close(p[STDERR_FILENO][1]);

		for(;;) {
			string input_line = readline(fd[STDERR_FILENO]);
			if(input_line.empty()) break;
			process_line(rdfOutput, input_line);
		}
		printf("END STDERR end\n");
        // success.
        return 0;
    } else {
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

static int execute_command(RdfOutput & rdfOutput, const vector<string> & command) {
	int fd[3];
	const char ** ptr_chars = new const char *[command.size() + 1];
	for(size_t index = 0; index < command.size(); ++index) {
		ptr_chars[index] = command[index].c_str();
	}
	ptr_chars[command.size()] = nullptr;

	printf("Command:");
	copy(ptr_chars, ptr_chars + command.size(), ostream_iterator<const char *>(logger(), " "));
	logger().flush();
	printf("\n");
	int ret = popen3(rdfOutput, fd, (char * const *)ptr_chars);
	delete[] ptr_chars;
	return ret;
}

/*******************************************************************************
**
** Replaying a log file containing the output of strace.
**
*******************************************************************************/
static int replay_strace_logfile(RdfOutput & rdfOutput, const string & replay_log) {
	ifstream infile(replay_log);
	string input_line;
	while(infile.good()){
		getline(infile, input_line);
		if(input_line.empty()) break;
		process_line(rdfOutput, input_line);
	}
	return 0;
}

/*******************************************************************************
**
** Processing the command line with strace and parsing the output.
**
*******************************************************************************/

class CommandExecutor {
	vector<string> m_command;
	string m_input_file;

public:
	/* The parameters can be a Linux command to execute in strace, or an input file to replay a session.*/
	CommandExecutor(vector<string> command) : m_command(command) {}
	
	/* This is the log of the execution of a previous strace run. */
	CommandExecutor(string input_file) : m_input_file(input_file) {}
	
	void Execute(RdfOutput & rdfOutput) {
		processed_lines = 0;
		if(m_input_file.empty()) {
			if(m_command.empty()) {
				throw runtime_error("No command given");
			}
			int ret = execute_command(rdfOutput, m_command);
			cout << "ret=" << ret << endl;
		} else {
			if(!m_command.empty()) {
				throw runtime_error("Command should be empty");
			}
			replay_strace_logfile(rdfOutput, m_input_file);
		}
		DefineSystemCallsClasses(rdfOutput);
		DefineCIMClasses(rdfOutput);
		cout << "Processed lines:" << processed_lines << endl;
	}
};


class CommandCreator {
	int argc;
	const char ** argv;
	string input_file;
	string output_file;
	const char * processid = nullptr;
	size_t index ;
public:
	CommandCreator(int input_argc, const char ** input_argv)
	: argc(input_argc)
	, argv(input_argv) {
		/*
		First come some options, then the command.
		*/
		index = 1;
		verbose_mode = 0;
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
				++verbose_mode;
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
			return CommandExecutor(input_file);
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
			return CommandExecutor(command);
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
