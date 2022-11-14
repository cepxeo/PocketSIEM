#key_names = ['Image', 'OR Image', 'NOT Image', 'OR NOT Image', 'CommandLine', 'OR CommandLine', 'NOT CommandLine', 'OR NOT CommandLine', 'CurrentDirectory', 'OR CurrentDirectory', 'NOT CurrentDirectory', 'OR NOT CurrentDirectory', 'Product', 'OR Product', 'NOT Product', 'OR NOT Product', 'OriginalFileName', 'OR OriginalFileName', 'NOT OriginalFileName', 'OR NOT OriginalFileName', 'ParentImage', 'OR ParentImage', 'NOT ParentImage', 'OR NOT ParentImage', 'ParentCommandLine', 'OR ParentCommandLine', 'NOT ParentCommandLine', 'OR NOT ParentCommandLine', 'ParentUser', 'OR ParentUser', 'NOT ParentUser', 'OR NOT ParentUser', 'IntegrityLevel', 'OR IntegrityLevel', 'NOT IntegrityLevel', 'OR NOT IntegrityLevel', 'Hashes', 'OR Hashes', 'NOT Hashes', 'OR NOT Hashes', 'Company', 'OR Company', 'NOT Company', 'OR NOT Company', 'Description', 'OR Description', 'NOT Description', 'OR NOT Description', 'User', 'OR User', 'NOT User', 'OR NOT User', 'LogonId', 'OR LogonId', 'NOT LogonId', 'OR NOT LogonId', 'FileVersion', 'OR FileVersion', 'NOT FileVersion', 'OR NOT FileVersion', 'Provider_Name', 'OR Provider_Name', 'NOT Provider_Name', 'OR NOT Provider_Name', 'OriginalName', 'OR OriginalName', 'NOT OriginalName', 'OR NOT OriginalName']
key_names_whitelist = ['ParentCommandLine', 'ParentImage', 'Image', 'CommandLine', 'OriginalFileName',
        'Description', 'Product', 'OriginalFileName', 'User',
        'TargetObject','NewName', 'Details', 'EventType', 'TargetFilename', 'DestinationIp', 
        'DestinationHostname','DestinationPort']

# Remove unnecessary symbols for dict keys and values
def clean_value(key):
    return key.replace("*", "").replace("\"", "").replace("(", "").replace(")", "").replace("!", "").replace("\\\\","\\").strip()

def add_key_value(key, value, patterns_dict):
    if key in key_names_whitelist:
        if key.split()[-1] in patterns_dict:
            for i in range(0,10):
                if key in patterns_dict:
                    key = "AND " + key
                else:
                    break
        patterns_dict[key] = [value]
    return patterns_dict

def add_or_key_value(key, value, patterns_dict):
    if key.split()[-1] in key_names_whitelist:
        if key in patterns_dict:
            for i in range(0,10):
                if key in patterns_dict:
                    key = "AND " + key
                else:
                    break
        patterns_dict[key] = value
    return patterns_dict