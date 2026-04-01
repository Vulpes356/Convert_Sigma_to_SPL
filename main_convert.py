import yaml
import json
import re
import os

# MAPPING
with open("logsource_mapping.json", "r") as file:
    LOGSOURCE_MAPPING = json.load(file)

#fix_fields
with open("fix_fields.json", "r") as f:
    fix_mapping = json.load(f)

def get_logsource_query(logsource, mapping):
    product = logsource.get('product')
    service = logsource.get('service')
    category = logsource.get('category')

    if not product or product not in mapping:
        return 'index=main'

    product_map = mapping[product]
    conf = None

    if service and service != 'NONE' and service in product_map:
        conf = product_map.get(service)
    elif category and category != 'NONE' and category in product_map:
        conf = product_map.get(category)
    else:
        conf = product_map.get('NONE')

    if conf:
        idx = conf.get('index', 'main')
        st = conf.get('sourcetype')
        filter_str = conf.get('filter', '')
        
        query_parts = [f"index=\"{idx}\""]
        if st:
            query_parts.append(f"sourcetype=\"{st}\"")
        if filter_str:
            query_parts.append(filter_str)
            
        return " ".join(query_parts)

    return "index=main"

def escape_splunk(val):
    return str(val).replace('\\', '\\\\')

def parse_single_condition(field_name, value):
    
    if not field_name or field_name.startswith('|'):
        modifiers = field_name.split("|")[1:] if "|" in field_name else []
        val = escape_splunk(value)
        return f'"*{val}*"'

    field = field_name.split("|")[0]
    modifiers = field_name.split("|")[1:] if "|" in field_name else []
    
    if isinstance(value, list):
        op = " AND " if "all" in modifiers else " OR "
        sub_queries = [parse_single_condition(field_name.replace("|all", ""), v) for v in value]
        return f"({op.join(sub_queries)})"


    val = escape_splunk((value))
    # print(f'{field}="{val}"')
    if field == "type":
        val = val.upper()

    if "re" in modifiers:
        return f'match({field}, "{(val)}")' 
    if "contains" in modifiers:
        return f'{field}="*{(val)}*"'
    if "endswith" in modifiers:
        return f'{field}="*{val}"'
    if "startswith" in modifiers:
        return f'{field}="{val}*"'
    
    return f'{field}="{val}"'

def get_detection_query(detection):
    condition = detection.get('condition', '')
    selections = {k: v for k, v in detection.items() if k != 'condition'}
    
    compiled_selections = {}
    for sel_name, sel_content in selections.items():
        if isinstance(sel_content, list):
            if all(isinstance(i, str) for i in sel_content):
                parts = [f'"*{escape_splunk(i)}*"' for i in sel_content]
                compiled_selections[sel_name] = f"({' OR '.join(parts)})"
            elif all(isinstance(i, int) for i in sel_content):
                parts = [f'{escape_splunk(i)}' for i in sel_content]
                compiled_selections[sel_name] = f"({' OR '.join(parts)})"
            else:
                parts = []
                for item in sel_content:
                    for k, v in item.items():
                        parts.append(parse_single_condition(k, v))
                compiled_selections[sel_name] = f"({' OR '.join(parts)})"
        else:
            parts = [parse_single_condition(k, v) for k, v in sel_content.items()]
            compiled_selections[sel_name] = f"({' AND '.join(parts)})"

    final_logic = condition
    final_logic = final_logic.replace(" and ", " AND ").replace(" or ", " OR "). replace(" not ", " NOT ")
    
    all_of_pattern = re.findall(r"all of (\w+\*)", final_logic)
    for match_term in all_of_pattern:
        prefix = match_term.replace("*", "")
        matches = [v for k, v in compiled_selections.items() if k.startswith(prefix)]
        final_logic = final_logic.replace(f"all of {match_term}", f"({' AND '.join(matches)})")

    n_of_pattern = re.findall(r"(\d+) of (\w+\*)", final_logic)
    for count, match_term in n_of_pattern:
        prefix = match_term.replace("*", "")
        matches = [v for k, v in compiled_selections.items() if k.startswith(prefix)]
        final_logic = final_logic.replace(f"{count} of {match_term}", f"({' OR '.join(matches)})")

    for sel_name, spl_snippet in compiled_selections.items():
        final_logic = final_logic.replace(sel_name, spl_snippet)

    return f" {final_logic}"

def parse_item(field_name, value):
    if "|" in field_name:
        field, modifier = field_name.split("|", 1)
        if modifier == "contains":
            return f'{field}="*{value}*"'
        if modifier == "endswith":
            return f'{field}="*{value}"'
    return f'{field_name}="{value}"'

def sigma_to_spl(yaml_content):
    data = yaml.safe_load(yaml_content)

    final_spl = ""
    logsource = data['logsource']
    final_spl += get_logsource_query(logsource, LOGSOURCE_MAPPING) + " "

    detection = data['detection']
    final_spl += get_detection_query(detection) + ""
    
    return (final_spl)
    
# main execution
def main_folder(sigma_folder, table_query):
    for filename in os.listdir(sigma_folder):
        if filename.endswith(".yml"):
            with open(os.path.join(sigma_folder, filename), "r") as file:
                content = file.read()
                spl_query = sigma_to_spl(content)
                
                if table_query:
                    table_query = " | table " + table_query

                for old_field, new_field in fix_mapping.items():
                    spl_query = spl_query.replace(old_field, new_field)
                print(f"From {filename}:\n{spl_query + table_query}\n")

def main_file(sigma_file, table_query):
    with open(sigma_file, "r") as file:
        content = file.read()
        spl_query = sigma_to_spl(content)
        
        if table_query:
            table_query = " | table " + table_query

        for old_field, new_field in fix_mapping.items():
            spl_query = spl_query.replace(old_field, new_field)
        print(f"From {sigma_file}:\n{spl_query +  table_query}\n")

import argparse

parser = argparse.ArgumentParser(description="Convert Sigma rules to SPL queries.")
parser.add_argument("--file", type=str, help="Path to a single Sigma file.")
parser.add_argument("--folder", type=str, help="Path to the folder containing Sigma files.")
parser.add_argument("--table", type=str, help="Table query for the final SPL query.")
args = parser.parse_args()
if args.folder:
    main_folder(args.folder, args.table or "")
elif args.file:    main_file(args.file, args.table or "")

