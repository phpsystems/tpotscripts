#!/usr/bin/env python
from __future__ import print_function
import json
import hashlib
import sys
from virus_total_apis import PublicApi as VirusTotalPublicApi
import inotify.adapters
import requests, json, os
from elasticsearch import Elasticsearch

API_KEY = '<Your VT API KEY Here>'

def setup():
#	res = requests.get('http://localhost:9200')
#	print (res.content)
	elast = Elasticsearch(
		['localhost'],
		http_auth=('<Elastic Username>', '<Elastic Password>'),
		scheme="https",
		port=64298,
		maxsize=1000
	)


	elast.indices.create(index='downloaded_files', ignore=400)
	return elast

def elasticimport(elast, filename, jsoncontents):
	print (elast.index(index='downloaded_files',doc_type='_doc', ignore=400, body=jsoncontents))

def scan(filename):
	filetest = filename.encode('utf-8')
	vt = VirusTotalPublicApi(API_KEY)

	response = vt.get_file_report(filetest)
	return(json.dumps(response, sort_keys=False, indent=4))

def _main():
	i = inotify.adapters.Inotify()
	i.add_watch(sys.argv[1])
	elast = setup()

	for event in i.event_gen(yield_nones=False):
		(_, type_names, path, filename) = event

#		print("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(path, filename, type_names))
#		PATH=[/data/dionaea/binaries/] FILENAME=[1f2029ef2b98e1bbe930d638691af9cd] EVENT_TYPES=['IN_CLOSE_WRITE']
		if format(type_names) == "['IN_CLOSE_WRITE']":
#			print "Filename: " + format(filename)
			filen, file_ext = os.path.splitext(format(filename))
			response = scan(filen)
			elasticimport(elast, filen ,response)
	
if __name__ == '__main__':
    _main()

