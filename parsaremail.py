import  os,hashlib,re,email,subprocess,requests,sys
from urllib.parse import urlparse

"""
# convert the msg file into eml === linux using a 3rd party tool named msgconvert
def conv_msg(msg):
    os.chdir("/home/bits/PycharmProjects/VT-scaneng/licenta/samples/")
    try:
        subprocess.run(["msgconvert " + msg], shell=True, check=True)
    except subprocess.CalledProcessError as err:
        print("error status:", err.returncode, "\n", "error output: ", err.output, "\n",
              "an error occurred, please check the name of the msg")
"""
# voi folosi ca o cale absoluta; daca voi cauta pe intreg sistemul de fisiere numele dat ca input, e posibil sa scaneze altceva in caz ca exista un fisier cu acelasi nume pe sistem dar in alta cale.
def conv_msg(msg):
    commandline=r"python3.6 /home/bits/Desktop/licenta/functionalitati/msgconv/outlookmsgfile.py" + " " + "/home/bits/Desktop/licenta/samples/" + msg
    '''    
    try:
        subprocess.run(commandline, shell=True, check=True)
        os.rename((msg+".eml"),(msg+".eml").replace(".msg",""))
        os.remove(msg)
    except subprocess.CalledProcessError as err:
        print("error status:", err.returncode, "\n", "error output:", err.output, "\n","an error occurred, please check the name of the msg")
    '''

# return a list with :sbj,snd,cc ...
def decode_header(msg):
    with open(r'/home/bits/Desktop/licenta/samples/' + msg) as mail:
        msg = email.message_from_file(mail)
    lst_header = {}
    lst_header["subject"] = msg.get("subject")
    lst_header["Message-ID"] = msg.get("Message-ID")
    '''
    msg.get("from") returneaza un string cu sender + Numele acestuia de la clientul de mail folosit
    folosesc utils.parseaddr sa imi returneze o tupla cu 2 stringuri:nume si sender
    '''


    lst_header["sender_email_address"] = email.utils.parseaddr(msg.get("from"))[1]
    lst_header["sender_name"] = email.utils.parseaddr(msg.get("from"))[0]

    try:
        if ((msg.get("CC")) != None):
            lst_header["CC"] = msg.get("Cc").split(",")
    except:
        lst_header["CC"] = ""

    lst_header["Date"] = msg.get("Date")
    lst_header["Servers_paths"] = msg.get_all("Received")
    lst_header["Received-SPF"] = msg.get("Received-SPF")
    lst_header['Authentication-Results'] = msg.get("Authentication-Results")
    lst_header["DKIM-Signature"] = msg.get("DKIM-Signature")

    return lst_header

def decode_body(msg):
    msg_name = msg[:]
    with open(r'/home/bits/Desktop/licenta/samples/' + msg) as mail:
        msg = email.message_from_file(mail)

    lst_body = {"attachments":[]}
    position=0
    for email_part in msg.walk():
        position+=1
        if 'multipart' in email_part.get_content_maintype():
            continue

        if "text/plain" in email_part.get_content_type():
            text = email_part.get_content_charset()
            if (text == None):
                lst_body["body"] = email_part.get_payload(decode=True)
            else:
                lst_body["body"] = email_part.get_payload(decode=True).decode(text,"ignore")

        if "text/html" in email_part.get_content_type():
            text = email_part.get_content_charset() ## in ce e incodat
            if (text == None):
                lst_body["part_" + str(position)] = email_part.get_payload(decode=True)
            else:
                lst_body["part_" + str(position)] = email_part.get_payload(decode=True).decode(text, "ignore")

        #if (email_part.get('Content-Disposition') != None):
        if email_part.get_filename() is not None:
            name = email_part.get_filename()
            #if name is not  None:
            filename = name
            lst_body["attachments"].append(filename)
            if (os.path.exists(r'/home/bits/Desktop/licenta/reports/' + msg_name + "/attachments") == False):
                os.mkdir(r'/home/bits/Desktop/licenta/reports/' + msg_name + "/attachments")
            path = r'/home/bits/Desktop/licenta/reports/' + msg_name + "/attachments/" 
            with open(os.path.join(path,filename),"wb") as file:
                file.write(email_part.get_payload(decode=True))
    return lst_body

def extract_urls_from_mail(lst_body):
    if "body" in lst_body:
        return re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', lst_body["body"])
    if "part_1" in lst_body:
        return re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', lst_body["part_1"])
    if "part_2" in lst_body:
        return re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', lst_body["part_2"])
    if "body" in lst_body and "part_1" in lst_body:
        dict["body"] = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', lst_body["body"])
        dict["part_1"] = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', lst_body["part_1"])
        return dict

    #it does not extract the relative paths only the absolute ones.
'''
        matching all of the below:
        'window.location = "http://www.example111.com";
            window.location.href = "http://www.example222.com";
            window.location.assign("http://www.example333.com");
            window.location.replace("http://www.example444.com");
            self.location = "http://www.example555.com";
            top.location = "http://www.example666.com"
	'''
