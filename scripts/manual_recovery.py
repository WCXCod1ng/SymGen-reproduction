import json

with open('/root/code/SymGen/all_dataset/checkpoint.json', 'r') as f:
    data = json.load(f)


print(len(data))

