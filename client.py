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
import requests

from sys import version as python_version
from cgi import parse_header, parse_multipart
import urllib

if python_version.startswith('3'):
	from urllib.parse import parse_qs, urlparse, unquote
	from urllib.request import urlopen
	from http.server import BaseHTTPRequestHandler, HTTPServer
	from io import BytesIO, StringIO
else:
	from urlparse import parse_qs, urlparse, unquote
	from urllib import urlopen
	from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
	try:
		from cStringIO import StringIO
	except ImportError:
		from StringIO import StringIO
	
import aes_enc

if python_version.startswith('3'):
	FILE_SIGNATURE = b"\x20\x18\x20\x18"
else:
	FILE_SIGNATURE = b"\x20\x18\x20\x18"

if python_version.startswith('3'):
	def s2b(str_):
		return bytes(str_, "u8")

	def b2s(bytes_):
		if type(bytes_) == bytes:
			return bytes_.decode("u8")
		else:
			return bytes_
else:
	def s2b(str_):
		return str_

	def b2s(bytes_):
		return bytes_
	
def upload_file(server_address, filename, data):
	if python_version.startswith('3'):
		s = BytesIO()
	else:
		s = StringIO()

	s.write(FILE_SIGNATURE + data)
	s.seek(0)
	try:
		requests.post(server_address, files={b2s(filename): s})
	except:
		print(filename)
		print(s)
		raise

class S(BaseHTTPRequestHandler):
	def _set_headers(self):
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()

	def parse_POST(self):
		ctype, pdict = parse_header(self.headers['content-type'])
		if python_version.startswith("3"):
			pdict['boundary'] = bytes(pdict['boundary'], "u8")

		if ctype == 'multipart/form-data':
			try:
				postvars = parse_multipart(self.rfile_backup, pdict)
			except:
				print(dir(self.rfile_backup))
				raise
		elif ctype == 'application/x-www-form-urlencoded':
			length = int(self.headers['content-length'])
			postvars = parse_qs(
					self.rfile_backup.read(length), 
					keep_blank_values=1)
		else:
			postvars = {}
		return postvars

	def do_GET(self):
		if self.path == "/upload" or self.path == "/":
			self._set_headers()
			try:
				self.wfile.write(s2b(open("upload.html", "r").read()))
			except:
				raise
		elif self.path.startswith("/file"):
			parsed_path = urlparse(self.path)
			if not parsed_path.query:
				self._set_headers()
				try:
					self.wfile.write(s2b(open("download.html", "r").read()))
				except:
					raise
				return

			print(self.path)

			server_address = unquote(parsed_path.query).split("=")[-1]
			print(server_address)
			remote_file_url = "%s%s" % (server_address, parsed_path.path)
			print(remote_file_url)
			
			server_data = urlopen(b2s(remote_file_url)).read()

			#print(server_data)
			try:
				server_data = eval(server_data)
			except:
				self.send_response(400)
				raise
			self.filename = unquote(b2s(server_data["name"]))
			decrypted_data = ENCRYPTOR.decrypt(server_data["data"])
			self.data = decrypted_data
			self.send_head()
			self.wfile.write(self.data)

		else:
			self.wfile.write(s2b("<html><body><h1>hi!</h1></body></html>"))

	def do_HEAD(self):
		self._set_headers()
		
	def get_filename(self):
		#print(self.post_data)
		try:
			h_start = self.post_data.index(s2b("Content-Disposition:")) + len("Content-Disposition:")
			#print(h_start)
			f_start = self.post_data.index(s2b("filename=\""), h_start) + len("filename=\"")
			#print(f_start)
			f_end = self.post_data.index(s2b("\""), f_start)
			#print(f_end)
			filename = self.post_data[f_start: f_end]
			print("filename: %s" % filename)
			return filename
		except:
			raise
			
	def read_POST(self):
		content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
		self.post_data = self.rfile.read(content_length) # <--- Gets the data itself
		if python_version.startswith("3"):
			self.rfile_backup = BytesIO()
		else:
			self.rfile_backup = StringIO()
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
		if self.path == "/upload" or self.path == "/":
			filename = self.get_filename()
			if not filename:
				print("file name not found!")
				self.send_response(400)
				return
			print("filename: %s" % filename)
			#print(postvars)
			server_address = postvars['server_address'][0]
			filedata = postvars["myfile"][0]
			encrypted_filedata = ENCRYPTOR.encrypt(filedata)
			upload_file(server_address, filename, encrypted_filedata)
			#if self.path == "/upload":
			#	print("vars = %s" % str(postvars))
			#print(self.rfile.read())
			try:
				file_id = b2s(urlopen("%s/id" % b2s(server_address)).read())
			except:
				self.send_response(400)
				raise
			self.wfile.write(s2b("""<html><body><h1>POST OK!</h1>""" +
							("""file id is %s<br>""" % file_id) +
							("""file URL <a href=\"http://localhost/file%s\">file%s</a>""" % (file_id, file_id)) +
							 """</body></html>"""))
		else:
			self.wfile.write(s2b("<html><body><h1>POST</h1></body></html>"))
		
def run(server_class=HTTPServer, handler_class=S, port = 80):
	server_address = ('', port)
	httpd = server_class(server_address, handler_class)
	print('Starting httpd...')
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		print("shutting down the server")
		httpd.shutdown()

def main():
	global APP_DIR, FILES_DIR, FILE_ID_PATH, ENCRYPTOR
	APP_DIR = os.path.join(os.environ.get("APPDATA", "/tmp"), "MyServer")
	FILES_DIR = os.path.join(APP_DIR, "Files")
	FILE_ID_PATH = os.path.join(APP_DIR, ".fileid")
	
	#ENCRYPTOR = rsa_enc.RSAEncryption()
	ENCRYPTOR = aes_enc.AESCipher(open("aes_key.txt", "r").read())

	if len(sys.argv) == 2:
		run(port = int(sys.argv[1]))
	else:
		run()

if __name__ == "__main__":
	main()
