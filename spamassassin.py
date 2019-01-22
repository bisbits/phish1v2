import subprocess, os

def spamassassin(email_sample):
    os.chdir("/home/bits/Desktop/licenta/samples/")
    output_file = "/home/bits/Desktop/licenta/reports/" + email_sample + "/spamassassin_report"
    error_file  = "/home/bits/Desktop/licenta/reports/" + email_sample + "/spamassassin_error"
    with subprocess.Popen(["spamassassin",email_sample], stdout = subprocess.PIPE, stderr = subprocess.PIPE) as proc:
        stdout = proc.stdout.read().decode("utf-8")
        stderr = proc.stderr.read().decode("utf-8")
    if len(stdout) != 0 :
        try:
            with open(output_file,"w") as raport:
                raport.write(stdout)
        except:
            print("nu s-a putut scrie raportul spamassassin in fisier")
        finally:
            if "X-Spam-Flag" in stdout:
                return "SPAM"
            else:
                return "NOT-SPAM"
    else:
        try:
            with open(error_file,"w") as raport:
                raport.write(stderr)
        except:
            print("nu s-a putut scrie cauza de ce a esuat spamassasssin sa analizeze mailul")
        finally:
            return "ERROR"
