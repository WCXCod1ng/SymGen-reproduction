import sys
import json
import os
import argparse
from tqdm import tqdm  # 建议添加 tqdm 显示进度，如果没有安装可删除相关代码

from antlr4 import *
from antlr.CLexer import CLexer
from antlr.CParser import CParser
from antlr.CVisitor import CVisitor

# 全局变量保持不变，供 Visitor 使用
lines = []
column_offset = {}
function_map = {}
function_count = 0


class SubstituteFunctionNameVisitor(CVisitor):
    def visitPostfixExpression(self, ctx: CParser.PostfixExpressionContext):
        global lines
        global column_offset
        global function_count
        global function_map

        if ctx.LeftParen() is not None and ctx.primaryExpression() is not None:
            if ctx.primaryExpression().Identifier() is not None:
                functionNameToken = ctx.primaryExpression().Identifier().getSymbol()
                if functionNameToken.text.startswith('FUN_'):
                    if functionNameToken.text in function_map.keys():
                        new_function_name = function_map[functionNameToken.text]
                    else:
                        new_function_name = 'FUN_' + str(function_count)
                        function_map[functionNameToken.text] = new_function_name
                        function_count += 1
                    # 进行字符串替换
                    lines[functionNameToken.line - 1] = lines[functionNameToken.line - 1][
                                                        0: functionNameToken.column + column_offset[
                                                            functionNameToken.line - 1]] + new_function_name + lines[
                                                                                                                   functionNameToken.line - 1][
                                                                                                               functionNameToken.column + len(
                                                                                                                   functionNameToken.text) +
                                                                                                               column_offset[
                                                                                                                   functionNameToken.line - 1]:]
                    column_offset[functionNameToken.line - 1] += len(new_function_name) - (len(functionNameToken.text))
        return self.visitChildren(ctx)


def substitute_decompiled(code):
    global lines
    global column_offset
    global function_map
    global function_count

    try:
        # 写入临时文件供 ANTLR 读取
        with open('code.txt', 'w') as file:
            file.write(code)

        with open('code.txt', 'r') as file:
            code = file.read()
            antlrInput = InputStream(code)

        with open('code.txt', 'r') as file:
            lines = file.readlines()

        for i in range(len(lines)):
            column_offset[i] = 0
        function_map = {}
        function_count = 0

        lexer = CLexer(antlrInput)
        stream = CommonTokenStream(lexer)
        parser = CParser(stream)
        tree = parser.compilationUnit()

        visitor = SubstituteFunctionNameVisitor()
        visitor.visit(tree)

        res = "".join(lines)

        if os.path.exists('code.txt'):
            os.remove('code.txt')

    except Exception as e:
        # print("exception:", str(e)) # 可以选择打印错误或忽略
        if os.path.exists('code.txt'):
            os.remove('code.txt')
        return None

    return res


def process_file_list(file_list, input_root_dir, existed_names, existed_bodies, is_training_mode=False):
    """
    处理文件列表的通用函数
    :param file_list: 包含相对路径的列表 ["arch/opt/proj/file", ...]
    :param input_root_dir: 数据集根目录
    :param existed_names: 全局已存在的函数名集合（用于去重）
    :param existed_bodies: 全局已存在的函数体集合（用于去重）
    :param is_training_mode: 如果是训练集，原逻辑使用 unstripped 代码；否则使用 stripped 代码
    :return: 处理好的样本列表
    """
    processed_samples = []

    # 使用 tqdm 显示进度条
    pbar = tqdm(file_list, desc="Processing")

    for relative_path in pbar:
        # 构建完整路径
        # 假设 json 中的路径已经是相对路径，例如 "arm/O0/project/file.json"
        # 如果 json 中没有后缀，这里可能需要加上 .json，根据你的描述假设包含完整文件名
        full_path = os.path.join(input_root_dir, relative_path)

        if not os.path.exists(full_path):
            # 尝试加 .json 后缀（防止提供的列表中没有后缀）
            if os.path.exists(full_path + '.json'):
                full_path += '.json'
            else:
                raise RuntimeError(f"Warning: File not found {full_path}")
                # continue

        try:
            with open(full_path, 'r') as f:
                data = json.load(f)
        except Exception:
            continue

        for function_name in data.keys():
            # 1. 过滤无意义的函数名
            if 'FUN_' in function_name:
                continue

            # 2. 函数名去重
            if function_name in existed_names:
                continue
            existed_names.append(function_name)

            # 3. 获取代码内容
            # 原逻辑：
            # 训练集：取 unstripped 用于 input (Sample['input']), 取 stripped 用于 substitute (Check)
            # 测试集：取 stripped 用于 input

            stripped_code = data[function_name].get('stripped', None)
            if stripped_code is None:
                continue

            # 无论训练还是测试，都使用 stripped 代码进行 substitute 处理来检查是否合法/去重
            modified_decompiled_code = substitute_decompiled(stripped_code)

            if modified_decompiled_code is None:
                continue

            # 4. 函数体内容去重
            if modified_decompiled_code in existed_bodies:
                continue
            existed_bodies.append(modified_decompiled_code)

            # 5. 构建样本
            # 关键：根据原代码逻辑，训练集使用的是 unstripped 代码作为 input
            if is_training_mode:
                input_code = data[function_name].get('unstripped', None)
                if input_code is None:
                    continue
            else:
                input_code = stripped_code  # 测试集和验证集使用 stripped 代码

            sample = {}
            sample[
                "instruction"] = "Suppose you are an expert in software reverse engineering. Here is a piece of decompiled code, you should infer code semantics and tell me the original function name from the contents of the function to replace [MASK]. Now the decompiled codes are as follows:"
            sample["input"] = input_code
            sample["output"] = 'The predicted function name is ' + function_name
            processed_samples.append(sample)

    return processed_samples


def main(args):
    input_dir = args.input_dir
    output_dir = args.output_dir

    # 1. 加载划分列表
    print(f"[+] Loading split lists...")
    try:
        with open(args.train_list, 'r') as f:
            train_files = json.load(f)
        with open(args.valid_list, 'r') as f:
            valid_files = json.load(f)
        with open(args.test_list, 'r') as f:
            test_files = json.load(f)
    except Exception as e:
        print(f"Error loading split files: {e}")
        return

    print(f"    Train files: {len(train_files)}")
    print(f"    Valid files: {len(valid_files)}")
    print(f"    Test files:  {len(test_files)}")

    # 2. 初始化全局去重集合
    # 注意：按照原代码逻辑，是先处理 Train，再 Test，再 Valid。
    # 这样 Test 和 Valid 中不会出现 Train 中已经出现过的函数。
    existed_function_name = []
    existed_function_body = []

    # 3. 处理数据集
    print("[+] Process Training Set Binary")
    train_data = process_file_list(
        train_files, input_dir, existed_function_name, existed_function_body, is_training_mode=True
    )

    print("[+] Process Test Set Binary")
    test_data = process_file_list(
        test_files, input_dir, existed_function_name, existed_function_body, is_training_mode=False
    )

    print("[+] Process Validation Set Binary")
    valid_data = process_file_list(
        valid_files, input_dir, existed_function_name, existed_function_body, is_training_mode=False
    )

    # 4. 保存结果
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    print(f"[+] Saving results to {output_dir}...")

    with open(os.path.join(output_dir, 'training_set.json'), 'w') as f:
        json.dump(train_data, f, indent=4)
        print(f"    Saved training_set.json ({len(train_data)} samples)")

    with open(os.path.join(output_dir, 'test_set.json'), 'w') as f:
        json.dump(test_data, f, indent=4)
        print(f"    Saved test_set.json ({len(test_data)} samples)")

    with open(os.path.join(output_dir, 'validation_set.json'), 'w') as f:
        json.dump(valid_data, f, indent=4)
        print(f"    Saved validation_set.json ({len(valid_data)} samples)")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate dataset from pre-defined split lists.')

    parser.add_argument('-i', '--input_dir', type=str, required=True,
                        help='Root directory containing the dataset files (structured as arch/opt/proj/file).')

    parser.add_argument('-o', '--output_dir', type=str, required=True,
                        help='Directory to save the processed dataset jsons.')

    # 新增参数：指定划分文件
    parser.add_argument('--train_list', type=str, required=True,
                        help='Path to the json file containing the list of training files.')
    parser.add_argument('--valid_list', type=str, required=True,
                        help='Path to the json file containing the list of validation files.')
    parser.add_argument('--test_list', type=str, required=True,
                        help='Path to the json file containing the list of test files.')

    args = parser.parse_args()
    main(args)