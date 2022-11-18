def run_check(rules_dict, field_names, or_field_names, date, host, image, details):

    """ Execute the check and save an alert in DB
    """
    for rule in rules_dict:
        flags = 0
        for key in rule.keys():
            for field in field_names.keys():
                if key[:3] == 'NOT':
                    if key.replace("NOT ", "").replace("AND ", "") == field and not all(item.casefold() in field_names[field].casefold() for item in rule[key]):
                        flags += 1
                        print(f"field: {field} flags {flags}")
                if key.replace("AND ", "") == field and all(item.casefold() in field_names[field].casefold() for item in rule[key]):
                    flags += 1
                    print(f"field: {field} flags {flags}")                

            for field in or_field_names.keys():
                if key[:3] == 'NOT':
                    if key.replace("NOT ", "").replace("AND ", "") == field and not any(item.casefold() in or_field_names[field].casefold() for item in rule[key]):
                        flags += 1
                        print(f"field: {field} flags {flags}")
                if key.replace("AND ", "") == field and any(item.casefold() in or_field_names[field].casefold() for item in rule[key]):
                    flags += 1
                    print(f"field: {field} flags {flags}")

        all_keys = len(rule.keys())
        print(f"flags: {flags}")
        print(f"keys: {all_keys}")
        if flags == all_keys:
            print(f"[!!] Event alert triggered by the process creation rule: {rule}")
            print(f"[!!] Malicious command: {details}")
            return

def check_process(date, host, image, command_line, parent_image, parent_command_line, proc_creation_patterns):
    field_names = {'ParentCommandLine':parent_command_line, 'ParentImage':parent_image, 'Image':image, 'CommandLine':command_line}
    or_field_names = {'OR ParentCommandLine':parent_command_line, 'OR ParentImage':parent_image, 'OR Image':image, 'OR CommandLine':command_line}

    run_check(proc_creation_patterns, field_names, or_field_names, date, host, image, command_line)