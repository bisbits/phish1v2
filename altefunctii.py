import hashlib, subprocess, os, shutil
from functionalitati.parsaremail import *

def calculate_hash(file):
    BLOCKSIZE = 65536
    hasher = hashlib.md5()
    with open(file, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return hasher.hexdigest()

def create_report(email):
	os.chdir("/home/bits/Desktop/licenta/reports")
	if email in os.listdir():
		try:
			import shutil
			shutil.rmtree("/home/bits/Desktop/licenta/reports/" + email)
			os.mkdir("/home/bits/Desktop/licenta/reports/" + email)
			os.mkdir("/home/bits/Desktop/licenta/reports/" + email + "/attachments" )
			os.mkdir("/home/bits/Desktop/licenta/reports/" + email + "/malware_samples")
			with open("/home/bits/Desktop/licenta/reports/" + email + "/sinteza_raport","w") as file:
				pass
		except:
			print("could not remove the existing report")
	else:
		os.mkdir("/home/bits/Desktop/licenta/reports/" + email)
		os.mkdir("/home/bits/Desktop/licenta/reports/" + email + "/attachments" )
		os.mkdir("/home/bits/Desktop/licenta/reports/" + email + "/malware_samples")
		with open("/home/bits/Desktop/licenta/reports/" + email + "/sinteza_raport","w") as file:
			pass

def extract_indicators_from_urls(urls_from_email):
    temp_list = extract_re

def file_hash(email):
    attachments_md5 = {}
    try:
        path=r'/home/bits/Desktop/licenta/reports/' + email + '/attachments/'
        os.chdir(path)
        for file in os.listdir("."):
            attachments_md5[file] = {}
            attachments_md5[file] = calculate_hash(file)
    except:
        print(" Nu s-a putut deschide directoriul atasamente din ", email)
    finally:
        return attachments_md5

def create_full_path_attachments(list_attachments,email_sample):
    for index in range(len(list_attachments)):
        list_attachments[index] = "/home/bits/Desktop/licenta/reports/" + email_sample + "/attachments/" + list_attachments[index]
    return list_attachments        