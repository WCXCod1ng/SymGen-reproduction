import json
import os

dataset_divided_folder = '/root/code/SymGen/dataset_divided' # 替换为实际存储“单独”划分之后的数据集的目录
architectures = ['arm_32', 'mips_32', 'x86_32', 'x86_64']
optimization_level = ['O0', 'O1', 'O2', 'O3']

filename = 'validation_set.json'

dataset = []
for arch in architectures:
    for level in optimization_level:
        path = os.path.join(dataset_divided_folder, arch, level, filename)
        print(path)
        # continue
        # 读取其中的数据（是一个列表）
        with open(path) as f:
            data = json.load(f)
        dataset.extend(data)

# 保存
with open(os.path.join(dataset_divided_folder, 'manual_aggregation', filename), 'w') as f:
    json.dump(dataset, f)