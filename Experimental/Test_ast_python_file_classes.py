from __future__ import print_function

import ast

def show_info(functionNode):
    print("Function name:", functionNode.name)
    print("f=", functionNode)
    print("f=", dir(functionNode))
    print("Args:")
    for arg in functionNode.args.args:
        #import pdb; pdb.set_trace()
        print("\tParameter name:", arg)


class MyClass:
    def f1(self):
        return "jj"

    @property
    def the_field(self):
      return self.an_the_field


filename = "Test_ast_python_file_classes.py"
with open(filename) as file:
    node = ast.parse(file.read())

functions = [n for n in node.body if isinstance(n, ast.FunctionDef)]
classes = [n for n in node.body if isinstance(n, ast.ClassDef)]

if False:
    print("")
    print("Functions")
    for function in functions:
        show_info(function)

print("")
print("Classes")
for class_ in classes:
    print("Class name:", class_.name)
    print("           ", dir(class_))
    for n in class_.body:
        decorators_names = [oned.id for oned in n.decorator_list]
        if 'property' in decorators_names:
            print("    Property n=", n.name)
        if False:
            # [<class '_ast.Name'>]
            print("                d=", [type(oned) for oned in n.decorator_list])
            print("                d=", [dir(oned) for oned in n.decorator_list])
            print("                d=", [oned.id for oned in n.decorator_list])
            #                 r= ['__class__', '__delattr__', '__dict__', '__doc__', '__format__', '__getattribute__', '__hash__', '__init__', '__
            # module__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weak
            # ref__', '_attributes', '_fields', 'args', 'body', 'col_offset', 'decorator_list', 'lineno', 'name']
            print("                a=", n.args)
            #                 a= ['__class__', '__delattr__', '__dict__', '__doc__', '__format__', '__getattribute__', '__hash__', '__init__', '__
            # module__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weak
            # ref__', '_attributes', '_fields', 'args', 'defaults', 'kwarg', 'vararg']
            print("                a=", n.args.kwarg)
            print("                t=", type(n))

    if False:
        methods = [n for n in class_.body if isinstance(n, ast.FunctionDef)]
        print("Methods only")
        for method in methods:
            print("    ")
            show_info(method)