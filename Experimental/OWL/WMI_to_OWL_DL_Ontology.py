from __future__ import print_function
import wmi

cnn = wmi.WMI()

cnt = 0

outfil = open(r"C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\Experimental\OWL\onto.owl","w")

map_attributes = {}

for class_name in cnn.classes:
    if cnt > 100: break
    cnt += 1

    cls_obj = getattr(cnn, class_name)
    drv_list = cls_obj.derivation()
    if drv_list:
        base_class_name = drv_list[0]
        outfil.write("""
        <OWL:Class rdf:ID="%s">
        <rdfs:subClassOf rdf:resource="#%s"/>
        </OWL:Class>\n""" % (class_name, base_class_name))

    for p in cls_obj.properties:
        prop_obj = cls_obj.wmi_property(p)

        try:
            only_read = prop_obj.qualifiers['read']
        except:
            only_read = False
        if not only_read:
            map_attributes[prop_obj.name] = prop_obj.type

map_types_CIM_to_OWL = {
    "string":"xsd:string"
}

for prop_name in map_attributes:
    prop_type = map_attributes[prop_name]
    try:
        owl_type = map_types_CIM_to_OWL[prop_type]
    except:
        owl_type = "xsd:" + prop_type
    outfil.write("""
    <OWL:DataTypeProperty rdf:ID="%s">
    <rdfs:domain rdf:resources="OWL:Thing"/>
    <rdfs:range rdf:resource="%s"/>
    </OWL:DataTypeProperty>\n""" % (prop_name, owl_type))

outfil.close()

print("OK")