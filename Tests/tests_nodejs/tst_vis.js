// provide data in the DOT language
var DOTstring = 'dinetwork {1 -> 1 -> 2; 2 -> 3; 2 -- 4; 2 -> 1 }';
var parsedData = vis.network.convertDot(DOTstring);

var data = {
  nodes: parsedData.nodes,
  edges: parsedData.edges
}

var options = parsedData.options;

// you can extend the options like a normal JSON variable:
options.nodes = {
  color: 'red'
}

// create a network
var network = new vis.Network(container, data, options);
