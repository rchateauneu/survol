print("Hello")

class UriDefault:
	def UriTo(self,entity_type,entity_id=None,entity_hostname=None,*kargs,**kwargs):
		return None

	def From(selfselg,cgiline):
		return None

class process:
	def To(self,entity_type,entity_id=None,entity_hostname=None,*kargs,**kwargs):
		return "?id=" + entity_id

	def From(self,cgiline):
		return { "id": "123"}

class UriDef:
	def __getattr__(self, name):
		def wrapper( *args, **kwargs):
			print "'%s' was called: args=%s kwargs=%s" % ( name , str(args), str(kwargs) )
		return wrapper

	def TheNormal(self):
		print("TheNormal")

	@staticmethod
	def ToUrl(classname,id):
		print("TheStatic "+classname+" "+str(id))

UriDef.ToUrl('process',123)

tc = UriDef()
# tc.TheNormal()
tc.CIM_Machin("aa",k1="v1",k2="v2")

tc.CIM_Process("bbbb")

def EnumArgs( nom = "Durand", prenom="Jean", *args, **kwargs):
	print "EnumArgs was called: nom=%s prenom=%s args=%s kwargs=%s" % ( str(nom) , str(prenom) , str(args), str(kwargs) )

EnumArgs(k1="v1",k2="v2")
EnumArgs("aa",k1="v1",k2="v2")
EnumArgs("aa","bb",k1="v1",k2="v2")
EnumArgs(prenom="aa",age="456",nom="bb",k1="v1",k2="v2")

EnumArgs(prenom="aa",age="456",nom="bb",k1="v1",k2="v2")