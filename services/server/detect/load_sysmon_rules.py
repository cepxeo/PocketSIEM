import re
#from detect.utils import clean_value, add_key_value, add_or_key_value
from utils import clean_value, add_key_value, add_or_key_value

def parse_pattern(pattern, patterns_dict):
    if pattern[0] == "(" and pattern[-1] == ")":
        pattern = re.search(r"\((.*)\)", pattern).group(1)
    in_blocks = pattern.split(' IN ')
    if len(in_blocks) > 1:
        for in_block in in_blocks:
            
            if in_blocks.index(in_block) == 0:
                continue
            previous_in_block = in_blocks[in_blocks.index(in_block) - 1]
            left_from_in_selection = previous_in_block.split(' ')

            # Key for IN occurence
            key = "OR " + clean_value(left_from_in_selection[-1])
            right_from_in = in_block

            # Value for IN occurence
            if ")" not in right_from_in:
                right_from_in += ")"
            value = clean_value(re.search(r"\((.*)\)", right_from_in).group(1)).strip().split(", ")
            patterns_dict = add_or_key_value(key, value, patterns_dict)

            # Parsing other keys to the left from IN
            if len(left_from_in_selection) > 1:
                print(f"left_from_in_selection {left_from_in_selection}")
                print(f"previous_in_block {previous_in_block}")
                for selection in previous_in_block.split('" '):
                    print(f"selection {selection}")
                    try:
                        key = clean_value(selection.split('=')[0].split()[-1])
                        value = clean_value(selection.split('=')[1])
                        patterns_dict = add_key_value(key, value, patterns_dict)
                    except:
                        pass
            
            if in_blocks.index(in_block) == len(in_blocks) - 1:
                #Parsing other keys to the right from the last IN block
                if len(right_from_in.split('") ')) > 1:
                    right_from_in_selection = right_from_in.split('") ')[1].split('" ')
                    for item in right_from_in_selection:
                        if '=' in item:
                            key = clean_value(item.split('=')[0].split()[-1])
                            value = clean_value(item.split('=')[1])
                            patterns_dict = add_key_value(key, value, patterns_dict)
    # If no IN, parse as simple space separated key=value pairs
    else:
        for selection in pattern.split('" '):
            try:
                key = clean_value(selection.split('=')[0].split()[-1])
                value = clean_value(selection.split('=')[1])
                patterns_dict = add_key_value(key, value, patterns_dict)
            except:
                pass
                #print(f"Error while parsing pattern: {pattern}")
  
    return patterns_dict

def load_rules(patterns_array, file, min_keys):
    with open(file, encoding="utf8") as f:
        for line in f:
            try:
                antipatterns_dict = {}
                if len(line.split(' NOT ')) > 1:
                    antipatterns = line.split(' NOT ')[1]
                    patterns = line.split(' NOT ')[0]

                    if antipatterns[0] == "(" and antipatterns[-2] == ")":
                        antipatterns = re.search(r"\((.*)\)", antipatterns).group(1)
                    antipatterns_dict == parse_pattern(antipatterns.replace(" OR ", " "), antipatterns_dict)
                    antipatterns_dict = dict(('NOT ' + key, value) for (key, value) in antipatterns_dict.items())
                else:
                    patterns = line
                patterns = patterns.split(' OR ')
                for pattern in patterns:
                    patterns_dict = {}
                    patterns_dict = parse_pattern(pattern, patterns_dict)

                    if len(patterns_dict.keys()) == 0: continue
                    patterns_dict = patterns_dict | antipatterns_dict
                    if min_keys == 2 and len(patterns_dict.keys()) < 2 and all(len(patterns_dict[item]) < 2 for item in patterns_dict.keys()): continue
                    patterns_array.append(patterns_dict)
            except:
                print(f"Defect line: {line}")
    f.close()
    return patterns_array