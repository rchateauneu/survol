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

/*
This extracts the function name so the right parser can be created.
*/
struct PreparsedLine {
	string function_name;
	size_t args_offset; // Points to the open parenthesis after the function name.

	PreparsedLine(const string & line) {
		const char * line_start = line.c_str();
		const char * time_end = strchr(line_start, ' ');
		if(time_end == nullptr) {
			throw std::runtime_error("No timestamp:" + line);
		}

		const char * function_start = time_end + 1;
		const char * function_end = strchr(function_start, '(');
		if(function_end == nullptr) {
			throw std::runtime_error("No function:" + line);
		}
		function_name.assign(function_start, function_end);
		args_offset = function_end - line_start;
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

static vector<string> ArgumentsParser(const string & line, size_t start_offset) {
	if(line[start_offset] != '(') {
		throw std::runtime_error("Wrong offset:" + line);
	}
	bool in_quotes = false;
	int balance_parenthesis = 1;
	vector<string> args;
	string current_arg;
	bool still_running = true;
	stack<char> enclosers;
	enclosers.push(')');
	for(size_t index = start_offset + 1; still_running && (index != line.size()); ++index) {
		const char chr = line[index];
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
	args.push_back(current_arg);
	return args;
}

/*
Internal test for a very important feature.
*/
struct test_definition {
	const char * input;
	const vector<const char *> outputs;
	test_definition(const char * the_input, initializer_list<const char *> the_outputs)
	: input(the_input)
	, outputs(the_outputs)
	{}
	
	void test() {
		cout << "Input=" << input << endl;
		vector<string> args = ArgumentsParser(input, 0);
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
	printf("Internal test end : OK.\n");
}

/*
Typical line displayed by the command strace:
17:17:06.968628 fstat(7</usr/share/zoneinfo/Europe/London>, {st_mode=S_IFREG|0644, st_size=3678, ...}) = 0 <0.000021>
*/
class STraceCall {
	// Today's timestamp.
	double m_seconds;
	vector<string> parsed_arguments;

public:
	STraceCall(const string & line, const PreparsedLine & preparsedLine) {
		const char * line_start = line.c_str();
		const char * time_end = strchr(line_start, ' ');
		if(time_end == nullptr) {
			throw std::runtime_error("No timestamp:" + line);
		}
		ParseTimestamp(line);
		try {
			parsed_arguments = ArgumentsParser(line, preparsedLine.args_offset);
		} catch(const exception & exc) {
			cerr << "Line=" << line << endl;
			throw;
		}
	}
	
	void ParseTimestamp(const string & time_start) {
		int hour, minutes;
		double seconds;
		int ret = sscanf(time_start.c_str(), "%d:%d:%lf", &hour, &minutes, &seconds);
		if(ret != 3) {
			throw std::runtime_error("Invalid time format:" + time_start);
		}
		m_seconds = hour * 24 * 3600 + minutes * 60 + seconds;
	};
	
	virtual const char * function() const = 0;
};

class STraceFactory {
public:
	typedef shared_ptr<STraceCall> (*Generator)(const string & line, const PreparsedLine & preparsedLine);

	static shared_ptr<STraceCall> factory(const string & line);
};
	

// 07:46:32.057886 connect(9<socket:[1552]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory) <0.000123>
class STraceCall_connect : public STraceCall {
public:
	STraceCall_connect(const string & line, const PreparsedLine & preparsedLine)
	: STraceCall(line, preparsedLine) {
	}
	const char * function() const override { return "connect";}
};

class STraceCall_openat : public STraceCall {
public:
	STraceCall_openat(const string & line, const PreparsedLine & preparsedLine)
	: STraceCall(line, preparsedLine) {
	}
	const char * function() const override { return "openat";}
};

template<class Derived>
shared_ptr<STraceCall> GenerTmpl(const string &line, const PreparsedLine & preparsedLine) {
	return make_shared<Derived>(line, preparsedLine);
}

map<string, STraceFactory::Generator> dict = {
	{"exit_group", nullptr },
	{"pread64", nullptr },
	{"brk", nullptr },
	{"arch_prctl", nullptr },
	{"mprotect", nullptr },
	{"mmap", nullptr },
	{"munmap", nullptr },
	{"read", nullptr },
	{"write", nullptr },
	{"close", nullptr },
	{"socket", nullptr },
	{"getdents64", nullptr },
	{"fstat", nullptr },
	{"ioctl", nullptr },
	{"lseek", nullptr },
	{"connect", GenerTmpl<STraceCall_connect> },
	{"openat", GenerTmpl<STraceCall_openat> },
};

shared_ptr<STraceCall> STraceFactory::factory(const string & line) {
	PreparsedLine preparsedLine(line);
	auto iter = dict.find(preparsedLine.function_name);
	if(iter == dict.end()) {
		throw runtime_error("Cannot find function:" + preparsedLine.function_name);
	}
	Generator gener = iter->second;
	if(gener == nullptr) {
		// throw runtime_error("Disabled function:" + preparsedLine.function_name);
		return shared_ptr<STraceCall>();
	}
	printf("INIT after l=%d KEY=%s\n", (int)dict.size(), preparsedLine.function_name.c_str());
	return gener(line, preparsedLine);
}


//static vector<shared_ptr<STraceCall>> calls;

static void process_line(const string &line) {
	try {
		shared_ptr<STraceCall> ptr = STraceFactory::factory(line);
		if(ptr.get() == nullptr) {
			return;
		}
		//calls.push_back(ptr);
		printf("Function=%s\n", ptr->function());
	} catch( const std::exception & exc) {
		printf("Caught:%s\n", exc.what());
		printf("RET=%s", line.c_str());
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
		result += c;
		if(c == '\n') break;
	}
	return result;
}


static int popen3(int fd[3],char * const * cmd) {
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
		printf("p[STDOUT_FILENO][0]=%d\n", p[STDOUT_FILENO][0]);
		printf("p[STDOUT_FILENO][1]=%d\n", p[STDOUT_FILENO][1]);
		printf("STDOUT_FILENO=%d\n", STDOUT_FILENO);
		printf("p[STDERR_FILENO][0]=%d\n", p[STDERR_FILENO][0]);
		printf("p[STDERR_FILENO][1]=%d\n", p[STDERR_FILENO][1]);
		printf("STDERR_FILENO=%d\n", STDERR_FILENO);

		char c;

		printf("END STDERR start\n");
		for(;;) {
			string ret = readline(fd[STDERR_FILENO]);
			if(ret.empty()) break;
			process_line(ret);
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
        // here we try and run it
		fprintf(stdout, "=================== STDOUT IN FORK\n");
		fprintf(stderr, "=================== STDERR IN FORK\n");

		// exit(0);
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

static int execute_command(const vector<string> & command) {
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
	int ret = popen3(fd, (char * const *)ptr_chars);
	delete[] ptr_chars;
	return ret;
}

/*******************************************************************************
**
** Processing the command line.
**
*******************************************************************************/
static int replay_strace_logfile(const string & replay_log) {
	ifstream infile(replay_log);
	string input_line;
	while(infile.good()){
		getline(infile, input_line);
		process_line(input_line);
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
public:
	/* The parameters can be a Linux command to execute in strace, or an input file to replay a session.*/
	CommandExecutor(vector<string> command) : m_command(command) {}
	
	/* This is the log of the execution of a previous strace run. */
	CommandExecutor(string input_file) : m_input_file(input_file) {}
	
	void Execute() {
		if(m_input_file.empty()) {
			if(m_command.empty()) {
				throw runtime_error("No command given");
			}
			// append_vector(command, vector<string>({"/usr/bin/ls", "-l", "-r"}));
			int ret = execute_command(m_command);
			printf("ret=%d\n", ret);
		} else {
			if(!m_command.empty()) {
				throw runtime_error("Command should be empty");
			}
			replay_strace_logfile(m_input_file);
		}
	}
};

/*
Same input arguments as strace, plus some extra.
*/
static CommandExecutor build_command(int argc, const char ** argv )
{
	string input_file;
	const char * processid = nullptr;
	
	/*
	First come some options, then the command.
	*/
	size_t index = 1;
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
		else if(0 == strcmp(arg, "-t")) {
			// Internal optional test.
			test_parsing();
		}
		else if(0 == strcmp(arg, "-h") || 0 == strcmp(arg, "-?")) {
			printf("%s -f <input file> -t -p <process id> command ....\n", argv[0]);
			exit(EXIT_SUCCESS);
		}
		else {
			break;
		}
    }

	if(! input_file.empty()) {
		if(processid != nullptr) {
			throw runtime_error("No pid should be given with an input file.");
		}
		if(index != argc) {
			throw runtime_error("No command should be given with an input file.");
		}
		return CommandExecutor(input_file);
	}

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
		//append_vector(command, vector<string>({"/usr/bin/ls", "-l", "-r"}));
	} else {
		if(index != argc) {
			throw runtime_error("A command and a pid are given. Should be one or the other.\n");
		}
		append_vector(command, vector<string>({"-p", processid}));
	}
	return CommandExecutor(command);
}

int main(int argc, const char ** argv)
{
	try {
		CommandExecutor executor = build_command(argc, argv);
		executor.Execute();
	} catch(const exception & exc) {
		fprintf(stderr, "Caught:%s\n", exc.what());
		exit(EXIT_FAILURE);
	}
	return 0;
}
