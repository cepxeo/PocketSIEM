import os
from pathlib import Path
from glob import glob

def load_rules(process_creation, path):
    basepath = Path(path)
    result = [y for x in os.walk(basepath) for y in glob(os.path.join(x[0], '*.yml'))]

    categories = []

    for file in result:
        with open(file) as f:
            for line in f:
                if "category" in line:
                    try:
                        category = line.split(":")[1]
                    except:
                        pass
                    if category not in categories:
                        categories.append(category)

                if "- '" in line or "-'" in line:
                    try:                    
                        command = line.split("'")[1].strip()
                        if command not in process_creation and command != "":
                            process_creation.append(command)
                    except:
                        print("Problem parsing sigma file " + file)
                        print("Defect line " + line)
    print(categories)
    return process_creation

def check_log(process_creation, entry):
    for pattern in process_creation:
        pattern_array = pattern.split("*")
        pattern_array = [i for i in pattern_array if i]
        match_pattern =  all(elem in entry for elem in pattern_array)
        filter_trash = all(len(elem) > 1 and elem[:1] != "." for elem in pattern_array)
        if match_pattern and filter_trash:
            return pattern