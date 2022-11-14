def load_rules(evil_patterns, file):
    with open(file) as f:
        for line in f:
            if "- '" in line or "-'" in line:
                try:
                    command = line.split("'")[1].strip()
                    if command not in evil_patterns and command != "":
                        evil_patterns.append(command)
                except:
                    print("Defect line " + line)
    f.close()
    return evil_patterns