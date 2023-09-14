# Read the Sigma YAML file paths into a dict and make a
# a copy for the target Kql queries
from pathlib import Path
from collections import defaultdict
import copy
from sigma.collection import SigmaCollection

rules_root = 'C:\\Users\\cseelhoff\\source\\repos\\auto-rule-enabler\\sigma\\sigma-master\\rules'
sigma_dict = defaultdict(dict)
for file in Path(rules_root).resolve().rglob("*.yml"):
    rel_path = Path(file).relative_to(rules_root)
    path_key = '.'.join(rel_path.parent.parts)
    sigma_dict[path_key][rel_path.name] = file
    
kql_dict = copy.deepcopy(sigma_dict)

eventIDs = {}
# Run the conversion
print("Converting rules")
conv_counter = {}
for categ, sources in sigma_dict.items():
    src_converted = 0
    #print("\n", categ, end="")
    for file_name, file_path in sources.items():
        print(file_path)
        #sigma, kql = sigma_to_la(file_path)

        #file_path = 'C:\\Users\\cseelhoff\\source\\repos\\auto-rule-enabler\\sigma\\sigma-master\\rules\\windows\\builtin\\shell_core\\win_shell_core_susp_packages_installed.yml'
        #try:
        with open(file_path, 'r', encoding="utf8") as input_file:
            sigma_txt = input_file.read()

        rules = SigmaCollection.from_yaml(sigma_txt)
        for rule in rules:
            #print(rule.detection)
            sigmaDetection = rule.detection
            for detect in sigmaDetection.detections:
                #print(detect)
                detection_values = sigmaDetection.detections[detect]
                #print(detection_values)
                for detection_item in detection_values.detection_items:
                    #if 'field' in detection_item:
                    if hasattr(detection_item, 'field'):
                        if detection_item.field == 'EventID':
                            #print(detection_item.value, end=" ")
                            for detection_item_value in detection_item.value:
                                #print(detection_item_value.number)
                                dictionary = eventIDs.get(detection_item_value.number, [])
                                dictionary.append(str(file_path))
                                eventIDs[detection_item_value.number] = dictionary
                            #print(detection_item.value[0].number)
                #if rule.logsource.product == 'windows':
                    #print(rule)
        #except Exception as err:
            #print(f"Error converting {file_path}")
            #print(err)
            #continue
#print(eventIDs)

#write eventIDs dictionary to json file
import json
with open('eventIDs.json', 'w') as fp:
    json.dump(eventIDs, fp)




