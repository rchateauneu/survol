#include <type_traits>

namespace semantic_layer {

class triple_store
{
public:
	template<class T>
	void declare_node()
	{
		rdf_stream << "<rdf" << _url << " " << "rdfs::type" << " " << rdf_type_name<T>() << ">";
	}

	template<class T>
	void declare_value(const T & value)
	{
		// Writes value only, with a timestamp ?
		rdf_stream << "<rdf" << _url << " " << "rdfs::value" << " rdf::literal" << _url << ">";
	}
private:
	std::ostream & rdf_stream;
};

class wrapper_base
{
protected:
	triple_store _store;
}

template<typename T, bool is_scalar_v = std::is_scalar<T>::value>
class wrapper;

template<typename T>
class wrapper<T, true> : wrapper_base
{
public:
	wrapper(const std::string & url);
	
	void serialize() const
	{
		_store.declare_node();
		_store.declare_value(_value);
	}
	
	// Writes value only, with a timestamp ?
private:
	const std::string _url;
	T _value;

};

template<typename T>
class wrapper<std::vector<T>, false>
{
public:
	wrapper(const std::string & url);
	void serialize() const
	{
		_store.declare_node();
		
		for(size_t idx=0; idx < _value.size(); ++idx) {
			// Add the index.
			_store.declare_value(_value[idx]);
		}
	}
private:
	const std::string _url;
	std::vector<T> _value;
};

/*
See intrusive lists ?
Boost::serialization because it can wrap existing data structures. But it needs a library.
The graph might or might not be stored along the values.
It might even be implicit, that is, represented in compiled code.
Thread-safety.
Stick to the logic of CGI scripts: An RDF document is created on demand.
A process is able to provide a RDF document about its internals, if a given symbol defined in the executable.

TODO: Use gdb to pick to global variables.

Starts a process or a thread creating a RDF endpoint ? A sparql end-point ?
This should be layered.

http://librdf.org/
Redland RDF Libraries
Sparql and triplestore are not needed: Only serialization. No extra storage.

*/


} // namespace