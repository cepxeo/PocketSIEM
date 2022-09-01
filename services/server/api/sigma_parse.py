import os
from pathlib import Path
from glob import glob

def load_rules(evil_patterns, path):
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
                        if command not in evil_patterns and command != "":
                            evil_patterns.append(command)
                    except:
                        print("Problem parsing sigma file " + file)
                        print("Defect line " + line)
    return evil_patterns

def check_log(evil_patterns, command_line):
    for pattern in evil_patterns:
        full_pattern_array = pattern.split("%")
        # Check for antipattern
        if len(full_pattern_array) > 1:
            if full_pattern_array[1] in command_line:
                return False
            pattern_array = full_pattern_array[0].split("*")
        else:
            pattern_array = pattern.split("*")
        pattern_array = [i for i in pattern_array if i]      
        match_pattern =  all(elem.casefold() in command_line.casefold() for elem in pattern_array)
        filter_trash = all(len(elem) > 1 for elem in pattern_array)
        if match_pattern and filter_trash:
            return pattern