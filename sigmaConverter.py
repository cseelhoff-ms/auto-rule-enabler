# Read the Sigma YAML file paths into a dict and make a
# a copy for the target Kql queries
from pathlib import Path
from collections import defaultdict
import copy
from sigma.collection import SigmaCollection
#from sigma.collection import SigmaDetection
from typing import Dict, Any
#from sigma.parser.modifiers import SigmaRuleLocation
#from sigma.parser.modifiers import SigmaModifiers
#from sigma.parser.condition import ConditionParser
from sigma.parser.exceptions import SigmaParseError

rules_root = 'C:\\Users\\cseelhoff\\source\\repos\\auto-rule-enabler\\sigma-master\\rules'
sigma_dict: Dict[str, Dict[str, Any]] = defaultdict(dict)
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

        with open(file_path, 'r', encoding="utf8") as input_file:
            sigma_txt = input_file.read()



        try:
            sigmaCollection: SigmaCollection = SigmaCollection.from_yaml(sigma_txt)
        except SigmaParseError as e:
            print(f"Error parsing {file_path}: {str(e)}")
            continue
        for rule in sigmaCollection.rules:
            #print(rule.detection)
            sigmaDetection = rule.detection
            for detection in sigmaDetection.detections:
                #print(detect)
                detection_values: sigma.rule.SigmaDetection = sigmaDetection.detections[detection]
                #print(detection_values)
                for detection_item in detection_values.detection_items:
                    #if 'field' in detection_item:
                    if hasattr(detection_item, 'field') and detection_item.field is not None:
                        field: str = detection_item.field
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




