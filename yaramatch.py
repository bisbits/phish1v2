import yara

'''
rules = yara.compile(filepaths={
    "malware_set1 rules": b"C:/Users/bits/Desktop/licenta/phishme/functionalitati/yararules/allrules.yar"})
'''

def yara_match(file_path, rules):
    try:
        matches = rules.match(file_path, timeout=90)
        return matches
    #except TimeoutError:
    #    print("the time is running out")
    except:
        print("Nu au putut fi compilate, posibil din cauza timeoutului prea mare. Este recomandat in situatia de fata sa compilati dinainte regulile YARA, apoi sa le incarcati.")
