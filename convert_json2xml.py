def json2xml(jsonfile,URL=False):
    try:
        from src.json2xml import Json2xml
    except:
        return "PLEASE INSTALL JSON2XML"
        break
    if URL == False:
        data = Json2xml.fromjsonfile(jsonfile).data
        data_object = Json2xml(data)
    
