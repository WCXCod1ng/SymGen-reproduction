import os
import json
import glob
import argparse
from tqdm import tqdm


def merge_json_files(file_pattern, output_path):
    """
    流式合并 JSON 文件，防止内存溢出。
    :param file_pattern: 文件匹配模式，例如 "dir/train_set_*.json"
    :param output_path: 输出文件路径
    """
    # 获取所有匹配的文件列表
    files = glob.glob(file_pattern)
    files.sort()  # 排序，保证合并顺序可复现

    if not files:
        print(f"[!] 未找到匹配的文件: {file_pattern}")
        return

    print(f"[-] 正在合并 {len(files)} 个文件到 -> {output_path}")

    total_samples = 0
    is_first_item = True

    try:
        with open(output_path, 'w', encoding='utf-8') as f_out:
            # 1. 写入 JSON 数组起始符号
            f_out.write('[\n')

            # 2. 遍历每个文件
            # 使用 tqdm 显示文件处理进度
            for file_path in tqdm(files, desc="Merging Files"):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f_in:
                        data = json.load(f_in)

                        if not isinstance(data, list):
                            print(f"Warning: {file_path} 不是列表格式，跳过。")
                            continue

                        # 3. 遍历文件中的每个样本并写入
                        for item in data:
                            if not is_first_item:
                                f_out.write(',\n')  # 如果不是第一个元素，前面加逗号和换行

                            # 将当前样本序列化写入文件
                            json.dump(item, f_out, ensure_ascii=False)

                            is_first_item = False
                            total_samples += 1

                except Exception as e:
                    print(f"Error reading {file_path}: {e}")

            # 4. 写入 JSON 数组结束符号
            f_out.write('\n]')

        print(f"[√] 合并完成: {output_path}")
        print(f"    总样本数: {total_samples}")

    except Exception as e:
        print(f"[!] 合并过程发生严重错误: {e}")


def main(args):
    input_dir = args.input_dir
    output_dir = args.output_dir

    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    # ================= 合并训练集 =================
    # 匹配模式：train_set_*.json (例如 train_set_arm_O0.json)
    train_pattern = os.path.join(input_dir, 'train_set_*.json')
    train_output = os.path.join(output_dir, 'aggregated_train_set.json')

    print(">>> 开始处理训练集...")
    merge_json_files(train_pattern, train_output)
    print("")

    # ================= 合并验证集 =================
    # 匹配模式：validation_set_*.json
    valid_pattern = os.path.join(input_dir, 'validation_set_*.json')
    valid_output = os.path.join(output_dir, 'aggregated_validation_set.json')

    print(">>> 开始处理验证集...")
    merge_json_files(valid_pattern, valid_output)
    print("")

    # ================= 测试集说明 =================
    print(">>> 测试集跳过合并")
    test_files = glob.glob(os.path.join(input_dir, 'test_set_*.json'))
    print(f"    检测到 {len(test_files)} 个测试集分片文件，保持原样以便分项测试。")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Merge split dataset files into single JSON files.')
    parser.add_argument('-i', '--input_dir', type=str, required=True,
                        help='Directory containing the split JSON files (e.g., train_set_arm_O0.json).')
    parser.add_argument('-o', '--output_dir', type=str, required=True,
                        help='Directory to save the merged training_set.json and validation_set.json.')

    args = parser.parse_args()
    main(args)