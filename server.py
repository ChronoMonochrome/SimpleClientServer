#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
import errno

from sys import version as python_version
from cgi import parse_header, parse_multipart

try:
	from cStringIO import StringIO
except ImportError:
	from StringIO import StringIO

if python_version.startswith('3'):
	from urllib.parse import parse_qs
	from http.server import BaseHTTPRequestHandler, HTTPServer
else:
	from urlparse import parse_qs
	from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
	
from SimpleHTTPServer import SimpleHTTPRequestHandler

# File ID
FILE_GLOBAL_ID = 0

# File signature
FILE_SIGNATURE = "\x20\x18\x20\x18"

# Post data ends with
POST_BOUNDARY_LEN = 40

class MyServer(BaseHTTPRequestHandler):
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
		self.rfile_backup = StringIO()
		self.rfile_backup.write(self.post_data)
		self.rfile_backup.seek(0)
		
	def send_head(self):
		self.send_response(200)
		self.send_header("Content-type", 'application/octet-stream')
		self.send_header("Content-Length", len(self.data))
		self.send_header('Content-Disposition', 'attachment; filename=%s' % self.filename)
		self.end_headers()

	def do_GET(self):
		if self.path.startswith("/file"):
			print("GET called")
			try:
				req_id = int(self.path.split("/file")[-1])
				#print("before send head")
				file_data = eval(open(os.path.join(FILES_DIR, str(req_id)), "rb").read())
				self.data = str(file_data)
				self.filename = file_data["name"]
				self.send_head()
				#print("after send head")
				self.wfile.write(self.data)
			except:
				catch()
				self.send_response(400)
		elif self.path == "/id":
			self._set_headers()
			self.wfile.write(str(get_file_id() - 1))
		else:
			self._set_headers()
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
			print("file name not found!")
			self.send_response(400)
			return
		
	def do_POST(self):
		global FILE_GLOBAL_ID
		self.read_POST()

		if not FILE_SIGNATURE in self.post_data:
			print("file signature not found!")
			self.send_response(400)
			return
			
		
		filename = self.get_filename()

		data_start = self.post_data.index(FILE_SIGNATURE) + len(FILE_SIGNATURE)
		parsed_data = self.post_data[data_start: -POST_BOUNDARY_LEN]
		#print(parsed_data)
		#print(post_data)
		print("file length: %d" % len(parsed_data))
		#print(self.headers)
		#print(self.headers)
		if (save_file(FILES_DIR, filename, parsed_data) < 0):
			print("error occured while receiving a file!")
			self.send_response(400)
			return
		self._set_headers()
		self.wfile.write("<html><body><h1>POST!</h1></body></html>")
		
def mkdir_p(path):
	try:
		os.makedirs(path)
	except OSError as exc:  # Python >2.5
		if exc.errno == errno.EEXIST and os.path.isdir(path):
			pass
		else:
			raise
			
# обработка всех исключений в коде - с выводом названия функции и строки
def catch(debug_info = ""):
	__func__ = sys._getframe().f_back.f_code.co_name
	exc_type, exc_obj, exc_tb = sys.exc_info()
	dbg_msg = "%s: %s on line %d: %s" %(__func__, exc_type, exc_tb.tb_lineno, exc_obj)
	if debug_info:
		dbg_msg += debug_info
	print(dbg_msg)
			
def get_file_id():
	path = FILE_ID_PATH
	id = 0
	if not os.path.exists(path):
		print("file id not found")
		return id

	try:
		id = eval(open(path, "r").read())
	except:
		catch()		
		
	return id
		
def set_file_id(id):
	def _remove_lock():
		try:
			if os.path.exists(lock_path):
				os.remove(lock_path)
		except:
			catch()

	path = FILE_ID_PATH
	lock_path = "%s.lock" % (path)
	if os.path.exists(lock_path):
		return -errno.EBUSY

	try:
		open(lock_path, "w").write("lock")
		open(path, "w").write(str(id))
	except:
		catch()
		_remove_lock()
		return -errno.EINVAL
		
	_remove_lock()
	return 0
	
def save_file(path, filename, filedata):
	id = get_file_id()
	filepath = os.path.join(path, str(id))
	res = dict()
	try:
		with open(filepath, "wb") as f:
			res["id"] = id
			res["name"] = filename
			res["data"] = filedata
			f.write(str(res))
			set_file_id(id + 1)
	except:
		catch()
		return -errno.EINVAL
	return 0

def run(server_class = HTTPServer, handler_class = MyServer, port = 8083):	
	server_address = ('', port)
	httpd = server_class(server_address, handler_class)
	print('Starting httpd...')
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		print("shutting down the server")
		httpd.shutdown()

def main():
	global APP_DIR, FILES_DIR, FILE_ID_PATH, FILE_GLOBAL_ID
	APP_DIR = os.path.join(os.environ.get("APPDATA", "/tmp"), "MyServer")
	FILES_DIR = os.path.join(APP_DIR, "Files")
	mkdir_p(FILES_DIR)
	FILE_ID_PATH = os.path.join(APP_DIR, ".fileid")
	if not os.path.exists(FILE_ID_PATH):
		set_file_id(FILE_GLOBAL_ID)
	
	FILE_GLOBAL_ID = get_file_id()
	print(FILE_GLOBAL_ID)

	if len(sys.argv) == 2:
		run(port = int(sys.argv[1]))
	else:
		run()

if __name__ == "__main__":
	main()
