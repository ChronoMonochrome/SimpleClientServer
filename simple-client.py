#!/usr/bin/env python
"""
Very simple HTTP server in python.

Usage::
	./dummy-web-server.py [<port>]

Send a GET request::
	curl http://localhost

Send a HEAD request::
	curl -I http://localhost

Send a POST request::
	curl -d "foo=bar&bin=baz" http://localhost

"""

import sys
import os
import StringIO
import urlparse
import requests

from sys import version as python_version
from cgi import parse_header, parse_multipart

import urllib

if python_version.startswith('3'):
	from urllib.parse import parse_qs
	from http.server import BaseHTTPRequestHandler, HTTPServer
else:
	from urlparse import parse_qs
	from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
	

import aes_enc

	
FILE_SIGNATURE = "\x20\x18\x20\x18"
	
def upload_file(server_address, filename, data):
	s = StringIO.StringIO()
	s.write(FILE_SIGNATURE + data)
	s.seek(0)
	r = requests.post(server_address, files={filename: s})

class S(BaseHTTPRequestHandler):
	def _set_headers(self):
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()

	def parse_POST(self):
		ctype, pdict = parse_header(self.headers['content-type'])

		if ctype == 'multipart/form-data':
			postvars = parse_multipart(self.rfile_backup, pdict)
		elif ctype == 'application/x-www-form-urlencoded':
			length = int(self.headers['content-length'])
			postvars = parse_qs(
					self.rfile_backup.read(length), 
					keep_blank_values=1)
		else:
			postvars = {}
		return postvars

	def do_GET(self):
		#print(self.path)
		#postvars = self.parse_POST()
		#print("vars = %s" % str(postvars))
		#print(self)
		#print(self.headers)
		if self.path == "/upload":
			self._set_headers()
			try:
				self.wfile.write(open("upload.html", "r").read())
			except:
				raise
		elif self.path.startswith("/file"):
			parsed_path = urlparse.urlparse(self.path)
			if not parsed_path.query:
				self._set_headers()
				try:
					self.wfile.write(open("download.html", "r").read())
				except:
					raise
				return

			print(self.path)

			server_address = urlparse.unquote(parsed_path.query).split("=")[-1]
			print(server_address)
			remote_file_url = "%s%s" % (server_address, parsed_path.path)
			print(remote_file_url)
			server_data = urllib.urlopen(remote_file_url).read()
			#print(server_data)
			try:
				server_data = eval(server_data)
			except:
				self.send_response(400)
				return
			self.filename = server_data["name"]
			decrypted_data = ENCRYPTOR.decrypt(server_data["data"])
			self.data = decrypted_data
			self.send_head()
			self.wfile.write(self.data)

		else:
			self.wfile.write("<html><body><h1>hi!</h1></body></html>")

	def do_HEAD(self):
		self._set_headers()
		
	def get_filename(self):
		try:
			h_start = self.post_data.index("Content-Disposition:") + len("Content-Disposition:")
			f_start = self.post_data.index("filename=\"", h_start) + len("filename=\"")
			f_end = self.post_data.index("\"", f_start)
			filename = self.post_data[f_start: f_end]
			print("filename: %s" % filename)
			return filename
		except:
			return
			
	def read_POST(self):
		content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
		self.post_data = self.rfile.read(content_length) # <--- Gets the data itself
		self.rfile_backup = StringIO.StringIO()
		self.rfile_backup.write(self.post_data)
		self.rfile_backup.seek(0)
		
	def send_head(self):
		self.send_response(200)
		self.send_header("Content-type", 'application/octet-stream')
		self.send_header("Content-Length", len(self.data))
		self.send_header('Content-Disposition', 'attachment; filename=%s' % self.filename)
		self.end_headers()
		
	def do_POST(self):
		# Doesn't do anything with posted data
		self._set_headers()
		#postvars = self.parse_POST()
		print("POST called")
		self.read_POST()

		postvars = self.parse_POST()
		if self.path == "/upload":
			filename = self.get_filename()
			if not filename:
				print("file name not found!")
				self.send_response(400)
				return
			print("filename: %s" % filename)
			print(postvars)
			#upload_file("http://localhost:8083", FILES_DIR, filename, postvars["myfile"][0])
			#print(type(postvars["myfile"][0]))
			server_address = postvars['server_address'][0]
			filedata = postvars["myfile"][0]
			encrypted_filedata = ENCRYPTOR.encrypt(filedata)
			upload_file(server_address, filename, encrypted_filedata)
			#if self.path == "/upload":
			#	print("vars = %s" % str(postvars))
			#print(self.rfile.read())
			try:
				file_id = urllib.urlopen("%s/id" % server_address).read()
			except:
				self.send_response(400)
				raise
			self.wfile.write("""<html><body><h1>POST OK!</h1>""" +
							("""file id is %s<br>""" % file_id) +
							("""file URL %s/file%s""" % (server_address, file_id)) +
							 """</body></html>""")
		else:
			self.wfile.write("<html><body><h1>POST</h1></body></html>")
		
def run(server_class=HTTPServer, handler_class=S, port = 80):
	server_address = ('', port)
	httpd = server_class(server_address, handler_class)
	print('Starting httpd...')
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		print("shutting down the server")
		httpd.shutdown()

if __name__ == "__main__":
	APP_DIR = os.path.join(os.environ.get("APPDATA", "/tmp"), "MyServer")
	FILES_DIR = os.path.join(APP_DIR, "Files")
	FILE_ID_PATH = os.path.join(APP_DIR, ".fileid")
	
	#ENCRYPTOR = rsa_enc.RSAEncryption()
	ENCRYPTOR = aes_enc.AESCipher(open("aes_key.txt", "r").read())

	if len(sys.argv) == 2:
		run(port = int(sys.argv[1]))
	else:
		run()
