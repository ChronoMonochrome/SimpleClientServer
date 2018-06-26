import os
import StringIO
import requests

def upload_file1(server_address, path):
	"""
	upload("http://localhost:8083", "C:/avatar.gif")
	"""
	with open(path, 'rb') as f:
		s = StringIO.StringIO()
		s.write(FILE_SIGNATURE + f.read())
		s.seek(0)
		r = requests.post(server_address, files = {os.path.basename(path), s})
		
def upload_file(server_address, path, filename, data):
	"""
	upload("http://localhost:8083", "C:/avatar.gif")
	"""
	s = StringIO.StringIO()
	s.write(FILE_SIGNATURE + data)
	s.seek(0)
	r = requests.post(server_address, files = {filename, s})
		
upload("http://localhost:8083", "G:/autorun.ico")