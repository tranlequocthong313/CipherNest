def file_extension(file):
    if len(file.name.split('.')) == 1:
        return ''
    return file.name.split('.')[-1].lower() 
