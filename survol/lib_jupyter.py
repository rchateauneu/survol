# This allows to easily handle Survol URLs in Jupyter.

# Server("127.0.0.1:8000").CIM_Process(Handle=1234) and Server("192.168.0.1:8000").CIM_Datafile(Name='/tmp/toto.txt')
#
class Server:
	# This works with an Url or a local script. Possibly with a static file.
	def __init__(self,address=None):
		self.m_address = address

		self.m_is_file = True

	# from IPython.display import HTML
	# HTML(url="http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.&mode=html")

	# from IPython.display import SVG
	# SVG(url='http://vps516494.ovh.net/Survol/survol/entity.py?xid=Linux/cgroup.Name=memory')

	def __url_with_mode(self,mode):
		# TODO: "?" or "&"
		return self.m_address + "?mode=" + mode

	# This executes the script and return the data in the right format.
	def __execute_script_with_mode(self,mode):
		# Sets an envirorment variable then imports the script and execute it.
		# TODO: "?" or "&"
		return "scripts_prefix/" + self.m_address + "?mode=" + mode

	# Output formats HTML, SVG, JSON, RDF. All are processed differently, so there is no need to unify.
	def __pair_display(self,mode):
		if self.IsScript():
			data_content = self.__execute_script_with_mode("html")
			return { "data" : data_content }

		if self.isUrl():
			the_url = self.__url_with_mode(mode)
			# Add the extension "?mode=html" or "svg" etc...
			return { "url" : the_url }

		raise Exception("This is unexpected")

	# Output formats HTML, SVG, JSON, RDF. All are processed differently, so there is no need to unify.
	def pair_html(self,mode):
		return self.__pair_display("html")

	def pair_svg(self,mode):
		return self.__pair_display("svg")

	def __content(self,mode):
		if self.IsScript():
			data_content = self.__execute_script_with_mode("html")
			return data_content

		if self.isUrl():
			the_url = self.__url_with_mode(mode)
			url_content = load_the_url(the_url)
			return the_url

		raise Exception("This is unexpected")

	def content_rdf(self):
		return self.__content("rdf")

	def content_json(self):
		return self.__content("json")




