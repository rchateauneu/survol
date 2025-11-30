export module straceparser;

import std;

using namespace std;


export class Triple {
	string subject, predicate, object;
};

export class TripleStore {
	vector<Triple> m_triples;
public:
	void display() const {};
};

export class SystemCall;

export class Line {
public:
	enum class LineState { Undefined, Normal, Unfinished, Resumed, Unsupported, EndOfFile };
	typedef int pid_type;
private:
	LineState m_state = LineState::Undefined;
	pid_type m_pid;
	string m_function;
	double m_execution_time;
	string m_return;
	chrono::high_resolution_clock::duration m_timestamp;
	string m_args_all;
	vector<string> m_args_split;

	void make_time(const smatch& mtch);
	void fill_from_match(const smatch& mtch);

	bool fill_from_string_normal(const string& input, size_t offset);
	bool fill_from_string_unfinished(const string& input, size_t offset);
	bool fill_from_string_resume(const string& input, size_t offset);
	bool fill_from_string_exit_group(const string& input, size_t offset);

	void merge_with_unfinished_call(const Line& unfinished_line);
public:
	Line(const string& content);
	int pid() const { return m_pid; }
	const string & return_value() const { return m_return; }
	double execution_time() const { return m_execution_time; }
	const string & function_name() const { return m_function; }
	const string& args_string() const { return m_args_all; }
	size_t args_count() const { return m_args_split.size(); }
	const string& arg_single(size_t index) const {
		return m_args_split.at(index);
	}
	string time_as_string() const;

	shared_ptr<SystemCall> create_system_call();

	inline static const double no_time = 0.0;
	inline static const pid_type no_pid = -1;
};

export class SystemCall {
public:
	virtual TripleStore create_triplestore() const {
		return TripleStore();
	}
};

export class STraceParser {
	string m_filename;
	ifstream m_file;
public:
	STraceParser(const string& filename);

	pair<Line::LineState, TripleStore> get_next_triplestore();

	~STraceParser();
};
