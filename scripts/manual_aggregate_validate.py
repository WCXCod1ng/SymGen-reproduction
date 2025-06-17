import json
import os

dataset_divided_folder = '../dataset_divided' # 替换为实际存储“单独”划分之后的数据集的目录
architectures = ['arm_32', 'mips_32', 'x86_32', 'x86_64']
optimization_level = ['O0', 'O1', 'O2', 'O3']

filename = 'training_set.json'

sum_size = 0
for arch in architectures:
    for level in optimization_level:
        path = os.path.join(dataset_divided_folder, arch, level, filename)
        print(path)
        # continue
        sum_size += os.path.getsize(path)

# 打开合并后的数据集
aggregated_file_size = os.path.getsize(os.path.join(dataset_divided_folder, "manual_aggregation", filename))
print(sum_size / 1024 / 1024, aggregated_file_size / 1024 / 1024)