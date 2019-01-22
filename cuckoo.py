import requests
import json
import time

# Arguments:
# file_path TEXT: path to the sample file
# package TEXT: analysis package to be used for the analysis
# timeout INTEGER (in seconds): analysis timeout
# priority INTEGER (1-3): priority to assign to the task
# options TEXT: options to pass to the analysis package
# machine TEXT: label of the analysis machine to use for the analysis
# platform TEXT (e.g. "windows"): name of the platform to select the analysis machine from
# tags TEXT: define machine to start by tags. Platform must be set to use that. Tags are comma separated
# custom TEXT: custom string to pass over the analysis and the processing/reporting modules
# owner TEXT: task owner in case multiple users can submit files to the same cuckoo instance
# clock TEXT (format %m-%d-%Y %H:%M:%S): set the virtual machine clock
# memory: enable the creation of a full memory dump of the analysis machine
# unique: only submit samples that have not been analyzed before
# enforce_timeout: enable to enforce the execution for the full timeout value

# de preferat sa fie folosit doar cand avem un singur fisier
def tasks_create_file(file, package= None, timeout= None, priority= None, options= None,
	machine= None, platform= None, tags= None, custom= None, owner= None,clock= None,
	 memory= None, unique= None, enforce_timeout= None):

	data_temp = {
		'package': package,
		'timeout': timeout,
		'priority': priority,
		'options': options,
		'machine': machine,
		'platform': platform,
		'tags': tags,
		'custom': custom,
		'owner': owner,
		'clock': clock,
		'memory': memory,
		'unique': unique,
		'enforce_timeout': enforce_timeout
		}

	data={}
	
	for index in data_temp:
		if data_temp[index] != None:
			data[index] = data_temp[index]

	with open(file, "rb" ) as sample:
		files = {"file": (file, sample)} # sample_file in cazul de fata va fi numele fisierului nostru pentru a nu aparea temp_file_name
		r = requests.post("http://localhost:8090" + "/tasks/create/file", files=files, data=data)
	
	if r.status_code != 200:
		return "Something went wrong"
	if r.status_code == 400:
		return "DUPLICATED_FILE_DETECTED"

	try:
		taskid = r.json()['task_id']
	except Exception as e:
		exception = "Something went wrong with the json: {0}".format(e)
		return exception

	return taskid

def tasks_create_submit(list):
#this function will retrieve a list with samples names
	if ("http://" in list[0]) or ("https://" in list[0]):
		r = requests.post( "http://localhost:8090/tasks/create/submit", data={"strings": "\n".join(urls)})
		if r.status_code == 200:
                        submit_id = r.json()["submit_id"]
                        task_ids = r.json()["task_ids"]
                        errors = r.json()["errors"]
                        return (submit_id, task_ids, errors)
		else:
			return "ERROR"
	filess = []
	for file in list:
		filess.append(("files", open(file, "rb")))

	r = requests.post( "http://localhost:8090" + "/tasks/create/submit" , files = filess)

	if r.status_code == 200:
                submit_id = r.json()["submit_id"]
                task_ids = r.json()["task_ids"]
                errors = r.json()["errors"]
                return (submit_id, task_ids, errors)
	else:
		return "ERROR"

def tasks_view(taskid):

	r = requests.get( "http://localhost:8090" + "/tasks/view/{0}".format(taskid))

	if r.status_code != 200:
		return "TASK NOT FOUND"

	status = r.json()['task']['status']
	return status
	# valori posibile pentru status= pending, running , completed, reported

def tasks_report(taskid):

	r = requests.get( "http://localhost:8090" + '/tasks/report/{0}'.format(taskid) )

	if r.status_code == 400:
		return "INVALID REPORT FORMAT"
	if r.status_code == 404:
		return "REPORT NOT FOUND"

	report = json.dumps(r.json())
	return report

def tasks_delete(taskid):

	r = requests.get( "http://localhost:8090" + "/tasks/delete/{0}".format(taskid))

	if r.status_code == 200:
		return "TASK DELETED"
	if r.status_code == 404:
		return "TASK NOT FOUND"
	if r.status_code == 500:
		return "UNABLE TO DELETE THE TASK"

def file_analysis(list, fisiersinteza):
	if len(list) == 0:
		fisiersinteza.write("Mailul nu contine fisiere pentru a fi analiza in sandbox")
	if len(list) == 1:
		response = tasks_create_file(list[0])
		fisiersinteza.write(str(response) + "  " + list[0])
		if type(response) == int:
			status_task = ""
			try:
				while status_task != 'reported':
					status_task=tasks_view(response)
					time.sleep(10)
			except:
				fisiersinteza.write("\n\t\t\tFisierul " + list[0] + " nu a putut fi vizualizat in Cuckoo")
			finally:
				if status_task == 'reported':
					fisiersinteza.write("\n\t\t\tFisierul " + list[0] + " are un scor de detectie de " +json.loads(tasks_report(response))["info"]["score"] + ". Pentru detalii suplimentare cum ar fi analiza bazata pe reguli YARA sau open threat intell feed-urile de la VirusTotal, vizualizati raportul atasat")
		else:
			fisiersinteza.write("fisierul " + list[0] + " nu a putut fi trimis la Cuckoo sa fie analizat. Verificati logurile pentru a afla de ce.")
	if len(list) > 1:
		for file in list:
			response = tasks_create_submit(file) # va returna o tupla de tipul submit_id, task_ids, errors
			if isinstance(response,tuple):
				submit_id = response[0]
				task_ids = response [1]
				index = 0 # va fi folosit ca index pentru a obtine numele atasamentelor
				for id in task_ids:
					status_tasks = ""
					try:
						while status_task != 'reported':  #	while status_task.encode("utf-8") != 'reported':
							status_task=tasks_view(id)
							time.sleep(10)
					except:
						fisiersinteza.write("\n\t\t\tFisierul " + list[index] + " nu a putut fi vizualizat in Cuckoo")
					finally:
						if status_task == 'reported':
							fisiersinteza.write("\n\t\t\tFisierul " + list[index] + " are un scor de detectie de " + str(json.loads(tasks_report(id))["info"]["score"]) + ". Pentru detalii suplimentare cum ar fi analiza bazata pe reguli YARA sau open threat intell feed-urile de la VirusTotal, vizualizati raportul atasat")
# trebuie atasat codul sa transform json-ul in xml si xml in html
			index += 1