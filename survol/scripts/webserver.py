#!/usr/bin/python
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
from os import curdir, sep
import cgi

PORT_NUMBER = 8765

# Used to:
# * Change on the fly the parameters.
# * See the internal status.

# There will be an extra class to set up some parameters that all daemons have.

# Each engine has a separate process:
# * Periodically wakes up to calculate data.
# * Serves HTTP queries to change the parameters.
# * Advertises as two SSDP services: One for the HTML page, the other one for the RDF file.

# The HTML page is a virtual: It can be generated on the fly, or we might wish
# to make a nice one with explanations etc...

class myHandler(BaseHTTPRequestHandler):
	
	#Handler for the GET requests
	def do_GET(self):
		if self.path=="/":
			self.path="/form.htm"

		try:
			#Check the file extension required and
			#set the right mime type

			sendReply = False
			mimetype=''
			if self.path.endswith(".html"):
				mimetype='text/html'
				sendReply = True
			if self.path.endswith(".htm"):
				mimetype='text/html'
				sendReply = True
			if self.path.endswith(".xml"):
				mimetype='text/xml'
				sendReply = True
			if self.path.endswith(".jpg"):
				mimetype='image/jpg'
				sendReply = True
			if self.path.endswith(".gif"):
				mimetype='image/gif'
				sendReply = True
			if self.path.endswith(".js"):
				mimetype='application/javascript'
				sendReply = True
			if self.path.endswith(".css"):
				mimetype='text/css'
				sendReply = True

                	print "Get path=" + self.path + " Mime=" + mimetype + " Send=" + str(sendReply)
			if sendReply == True:
				#Open the static file requested and send it
				f = open(curdir + sep + self.path) 
				self.send_response(200)
				self.send_header('Content-type',mimetype)
				self.end_headers()
				self.wfile.write(f.read())
				f.close()
			return

		except IOError:
			self.send_error(404,'File Not Found: %s' % self.path)

	#Handler for the POST requests
	def do_POST(self):
                print "Post path=" + self.path
		if self.path=="/":

			form = cgi.FieldStorage(
				fp=self.rfile, 
				headers=self.headers,
				environ={'REQUEST_METHOD':'POST',
		                 'CONTENT_TYPE':self.headers['Content-Type'],
			})

                        for theKey in form:
                            print "Key=%s is: %s" % ( theKey, form[theKey].value )
			self.send_response(200)
			self.end_headers()
			self.wfile.write("Result\r\n")
                        for theKey in form:
                            self.wfile.write( "Key=%s is: %s\r\n" % ( theKey, form[theKey].value ) )
			return			
			
			
try:
	#Create a web server and define the handler to manage the
	#incoming request
	server = HTTPServer(('', PORT_NUMBER), myHandler)
	print 'Started httpserver on port ' , PORT_NUMBER
	
	#Wait forever for incoming htto requests
	server.serve_forever()

except KeyboardInterrupt:
	print '^C received, shutting down the web server'
	server.socket.close()
