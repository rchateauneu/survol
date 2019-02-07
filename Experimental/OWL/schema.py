#
# (c)2005 LIRIS - University Claude Bernard Lyon 1
# http://liris.cnrs.fr/
#
# Author: Pierre-Antoine CHAMPIN
# http://champin.net/
#
# This software is distributed under the terms of the GNU LGPL v2.1.
# See LICENSE.txt for more details.
#

from cross.ns               import OWL, XSD
from cross.datasource.utils import *

from rdflib import BNode, Graph, Literal, RDF, RDFS, URIRef

from itertools import izip


def schemaGraph (ds, ns, ontology_uri=None):
    """
    schemaGraph (datasource, namespace, [ontology_uri,])

    Return an RDF graph filled with axioms describing the datasource.
    
    @param ds:           the DataSource whose schema has to be converted
    @param ns:           the namespace uri of the created classes and properties
    @param ontology_uri if not given, the namespace uri is used

    @see: L{cross.datasource}
    """

    # naming scheme:
    #   t-tablename : table class
    #   c-tablename.columnname : column property
    #   _ic-tablename.columnname : inverse column property
    #   _vc-tablename.columnname.simple_val : column-value instance
    #   dc-tablename.columnname : column-data property
    #   nc-tablename.columnname : null-column class
    #   i-tablename.indexname : index property
    #   _ii-tablename.indexname : inverse index property
    #   _vi-tablename.indexname.tuple_val : index-value instance
    #   di-tablename.indexname : index-data property
    #   ni-tablename.indexname : null-index class
    #   f-tablename.foreignkeyname : foreign-key property
    #   _vf-tablename.foreignkeyname.tuple_val : foreign-key-value instance
    #   df-tablename.foreignkeyname : foreign-key property
    #   nf-tablename.foreignkeyname : null-foreign-key class

    rdf = Graph()
    rdf.bind ('xsd',  XSD)
    rdf.bind ('owl',  OWL)

    if ontology_uri is None:
        ontology_uri = ns
        if ontology_uri[-1] in ['#', '/']:
            ontology_uri = ontology_uri[:-1]
    ontology_uri = URIRef (ontology_uri)

    rdf.add ((ontology_uri, RDF.type, OWL.Ontology))
    rdf.add ((RDF.value,    RDF.type, OWL.DatatypeProperty))

    for t in ds.tables:
        t_uri = URIRef ("%st-%s" % (ns, t.uri_name))
        _manage_table (t_uri, t, ns, rdf)

        for c in t.columns:
            _manage_column (t_uri, c, ns, rdf)

        for i in t.unique_indexes:
            if len (i) > 1:
                _manage_unique_index (t_uri, i, ns, rdf)

        for f in t.foreign_keys:
            _manage_foreignkey (t_uri, f, ns, rdf)
            

    return rdf

def _manage_table (t_uri, table, ns, rdf):
    rdf.add ((t_uri, RDF.type, OWL.Class))

    ## primary key
    #pk = table.primary_key
    #if len (pk) == 1:
    #    pk_uri = URIRef ("%sc-%s" % (ns, pk[0].uri_name))
    #else:
    #    pk_uri = URIRef ("%si-%s" % (ns, pk.uri_name))
    ## it appears that we don't do anything special for the PK

def _manage_column (t_uri, c, ns, rdf):
    c_uri = URIRef ("%sc-%s" % (ns, c.uri_name))
    cv_id = URIRef("%s_vc-%s" % (ns, c.uri_name)) # TODO change to blank?
    #cv_id = BNode()

    rdf.add (( c_uri, RDF.type,    OWL.ObjectProperty))
    rdf.add (( c_uri, RDF.type,    OWL.FunctionalProperty))
    rdf.add (( c_uri, RDFS.domain, t_uri ))
    rdf.add (( c_uri, RDFS.range,  cv_id ))

    rdf.add (( cv_id, RDF.type,    OWL.Class ))

    # column property must be present if not nullable
    if not c.nullable:
        rdf.add ((
            t_uri,
            RDFS.subClassOf,
            _restriction ( rdf,
                c_uri,
                OWL.minCardinality,
                1,
            )
        ))
    # column property inverse-functional if unique
    if c.unique:
        rdf.add (( c_uri, RDF.type, OWL.InverseFunctionalProperty))
    # class for null-value
    if c.nullable:
        null_uri = URIRef ("%snc-%s" % (ns, c.uri_name))
        rdf.add ((null_uri, RDF.type, OWL.Class))
        rdf.add ((
            null_uri,
            RDFS.subClassOf,
            _restriction ( rdf,
                c_uri,
                OWL.maxCardinality,
                0,
            )
        ))

    d_uri  = URIRef ("%sdc-%s" % (ns, c.uri_name))
    rdf.add (( d_uri, RDF.type,    OWL.ObjectProperty))
    rdf.add (( d_uri, RDF.type,    OWL.FunctionalProperty))
    rdf.add (( d_uri, RDF.type,    OWL.InverseFunctionalProperty))
    rdf.add (( d_uri, RDFS.domain, cv_id))

    # column-data property range
    rdf.add ((
        cv_id,
        OWL.equivalentClass,
        _restriction ( rdf,
            d_uri,
            OWL.someValuesFrom,
            _restriction ( rdf,
                RDF.value,
                OWL.someValuesFrom,
                c.datatype.xsd,
            )
        )
    ))

def _manage_unique_index (t_uri, i, ns, rdf):
    i_uri = URIRef ("%si-%s" % (ns, i.uri_name))

    _manage_index_common (t_uri, i_uri, i, "i", ns, rdf)

    rdf.add (( i_uri, RDF.type,    OWL.InverseFunctionalProperty))

    iv_id = URIRef ("%s_vi-%s" % (ns, i.uri_name)) # TODO change to blank?
    #iv_id = BNode()
    rdf.add (( iv_id, RDF.type,   OWL.Class ))
    rdf.add (( i_uri, RDFS.range, iv_id ))

    d_uri  = URIRef ("%sdi-%s" % (ns, i.uri_name))
    rdf.add (( d_uri, RDF.type,    OWL.ObjectProperty))
    rdf.add (( d_uri, RDF.type,    OWL.FunctionalProperty))
    rdf.add (( d_uri, RDF.type,    OWL.InverseFunctionalProperty))
    rdf.add (( d_uri, RDFS.domain, iv_id))

    # index-data property range
    rdf.add ((
        iv_id,
        OWL.equivalentClass,
        _restriction ( rdf,
            d_uri,
            OWL.minCardinality,
            1,
        )
    ))

def _manage_foreignkey (t_uri, f, ns, rdf):

    f_nullable = f.nullable
    f_single_col = (len (f) == 1)

    # column-values from the foreign key are comparable with the ones they are
    # pointing to
    for fc,pc in izip (f.effective_order, f.pindex):
        dfc_uri = URIRef ("%sdc-%s" % (ns, fc.uri_name))
        dpc_uri = URIRef ("%sdc-%s" % (ns, pc.uri_name))
        rdf.add (( dfc_uri, RDFS.subPropertyOf, dpc_uri ))

        if f_single_col or not f_nullable:
            # NB: if f is nullable and has several columns, as soon as one
            # column is NULL, the others are no longer constrained to take
            # their value in ptable, hence the condition above
            fc_uri = URIRef ("%sc-%s" % (ns, fc.uri_name))
            pc_uri = URIRef ("%sc-%s" % (ns, pc.uri_name))
            rdf.add ((
                fc_uri,
                RDFS.range,
                _restriction ( rdf,
                    _inverseOf ( rdf, pc_uri ),
                    OWL.minCardinality,
                    1
                )
            ))

            

    if not f_single_col:
        f_uri = URIRef ("%sf-%s" % (ns, f.uri_name))

        _manage_index_common (t_uri, f_uri, f, "f", ns, rdf)
        
        # foreign key property inverse-functional if unique
        if f.unique:
            rdf.add (( f_uri, RDF.type, OWL.InverseFunctionalProperty))

        # foreign key value is actually the one of the corresponding pindex
        # and must be the value of an existing row
        pi_uri = URIRef ("%si-%s" % (ns, f.pindex.uri_name))
        rdf.add ((
            f_uri,
            RDFS.range,
            _restriction ( rdf,
                _inverseOf ( rdf, pc_uri ),
                OWL.minCardinality,
                1
            )
        ))


def _manage_index_common (t_uri, i_uri, i, type, ns, rdf):

    rdf.add (( i_uri, RDF.type,    OWL.ObjectProperty))
    rdf.add (( i_uri, RDF.type,    OWL.FunctionalProperty))
    rdf.add (( i_uri, RDFS.domain, t_uri ))

    # index property must be present if no column is nullable
    if not i.nullable:
        rdf.add ((
            t_uri,
            RDFS.subClassOf,
            _restriction ( rdf,
                i_uri,
                OWL.minCardinality,
                1,
            )
        ))
    # class for null-value
    if i.nullable:
        null_uri = URIRef ("%sn%s-%s" % (ns, type, i.uri_name))
        rdf.add ((null_uri, RDF.type, OWL.Class))
        rdf.add ((
            null_uri,
            RDFS.subClassOf,
            _restriction ( rdf,
                i_uri,
                OWL.maxCardinality,
                0,
            )
        ))


def _restriction (rdf, property, operator, argument):
    if isinstance (argument, int):
        argument = Literal (unicode(argument), datatype=XSD.integer)
    r = BNode ()
    rdf.add ((r,   RDF.      type,   OWL.Restriction))
    rdf.add ((r,   OWL.onProperty,          property))
    rdf.add ((r,         operator,          argument))
    return r

def _inverseOf (rdf, property):
    #p = BNode ()
    p = URIRef (property+"_inv")
    # using a BNode causes Pellet to behave erratically
    rdf.add ((p, RDF.type,      OWL.ObjectProperty))
    rdf.add ((p, OWL.inverseOf, property))
    return p


