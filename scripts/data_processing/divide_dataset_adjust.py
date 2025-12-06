import sys
import json
import os
import argparse
import gc  # 引入垃圾回收机制
from tqdm import tqdm

from antlr4 import *
from antlr.CLexer import CLexer
from antlr.CParser import CParser
from antlr.CVisitor import CVisitor

# ================= 全局变量与 Visitor (保持原逻辑不变) =================
lines = []
column_offset = {}
function_map = {}
function_count = 0


class SubstituteFunctionNameVisitor(CVisitor):
    def visitPostfixExpression(self, ctx: CParser.PostfixExpressionContext):
        global lines, column_offset, function_count, function_map
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
    global lines, column_offset, function_map, function_count
    try:
        # 考虑到并发写入风险，使用pid作为临时文件名的一部分，或者假设是单进程运行
        temp_filename = f'code_{os.getpid()}.txt'
        with open(temp_filename, 'w') as file:
            file.write(code)

        with open(temp_filename, 'r') as file:
            code_content = file.read()
            antlrInput = InputStream(code_content)

        with open(temp_filename, 'r') as file:
            lines = file.readlines()

        column_offset = {i: 0 for i in range(len(lines))}
        function_map = {}
        function_count = 0

        lexer = CLexer(antlrInput)
        stream = CommonTokenStream(lexer)
        parser = CParser(stream)
        tree = parser.compilationUnit()

        visitor = SubstituteFunctionNameVisitor()
        visitor.visit(tree)

        res = "".join(lines)
        if os.path.exists(temp_filename): os.remove(temp_filename)
        return res
    except Exception:
        if os.path.exists(temp_filename): os.remove(temp_filename)
        return None


# ================= 处理逻辑 =================

def filter_file_list(file_list, target_arch, target_opt):
    """
    从总列表中筛选出符合当前 架构/优化等级 的文件路径
    假设路径格式: arch/opt/project/file
    """
    filtered = []
    # 构造匹配前缀，如 "arm/O0"
    prefix = f"{target_arch}/{target_opt}"

    for f in file_list:
        # 统一路径分隔符并检查前缀
        normalized_path = f.replace('\\', '/')
        if normalized_path.startswith(prefix):
            filtered.append(f)
    return filtered


def process_file_list(file_list, input_root_dir, existed_names, existed_bodies, is_training_mode=False):
    processed_data = []

    # 使用 tqdm 时，如果不显示进度条可以减少打印带来的IO开销，这里保留但在Shell调用时可忽略
    for relative_path in tqdm(file_list, desc="Processing", leave=False):
        full_path = os.path.join(input_root_dir, relative_path)

        # 容错处理：尝试添加 .json 后缀
        if not os.path.exists(full_path):
            if os.path.exists(full_path + '.json'):
                full_path += '.json'
            else:
                continue

        try:
            with open(full_path, 'r') as f:
                data = json.load(f)
        except Exception:
            continue

        # 显式内存管理：处理完一个文件后，确保 data 引用被释放（Python作用域自动处理，但手动注意更好）
        for function_name in list(data.keys()):  # list()创建副本，允许修改字典或安全遍历
            if 'FUN_' in function_name: continue

            # 去重
            if function_name in existed_names: continue

            stripped_code = data[function_name].get('stripped', None)
            if stripped_code is None: continue

            # 清洗
            modified_decompiled_code = substitute_decompiled(stripped_code)
            if modified_decompiled_code is None: continue

            # 内容去重
            if modified_decompiled_code in existed_bodies: continue

            # 这里先添加到去重集合，确保当前 Batch 内不重复
            # 注意：跨 Batch 的去重（比如 O0 和 O1 之间）在这个方案中被牺牲了，
            # 除非引入外部数据库（Redis）。但题目要求按架构/优化等级分开处理，
            # 通常意味着只需保证该组合内的唯一性，或接受不同优化等级间的重复。
            existed_names.append(function_name)
            existed_bodies.append(modified_decompiled_code)

            # 构建样本
            if is_training_mode:
                input_code = data[function_name].get('unstripped', None)
                if input_code is None: continue
            else:
                input_code = stripped_code

            sample = {
                "instruction": "Suppose you are an expert in software reverse engineering. Here is a piece of decompiled code, you should infer code semantics and tell me the original function name from the contents of the function to replace [MASK]. Now the decompiled codes are as follows:",
                "input": input_code,
                "output": 'The predicted function name is ' + function_name
            }
            processed_data.append(sample)

    return processed_data


def save_json(data, output_path):
    """单独的保存函数"""
    if not data:
        return
    try:
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"    Saved: {output_path} ({len(data)} samples)")
    except Exception as e:
        print(f"    Error saving {output_path}: {e}")


def main(args):
    input_dir = args.input_dir
    output_dir = args.output_dir
    target_arch = args.arch
    target_opt = args.opt

    prefix_name = f"{target_arch}_{target_opt}"
    print(f"[-] Starting process for: {prefix_name}")

    # 1. 加载所有列表 (文件列表本身通常不大，MB级别，可以加载)
    try:
        with open(args.train_list, 'r') as f:
            train_files_all = json.load(f)
        with open(args.valid_list, 'r') as f:
            valid_files_all = json.load(f)
        with open(args.test_list, 'r') as f:
            test_files_all = json.load(f)
    except Exception as e:
        print(f"Error loading split lists: {e}")
        return

    # 2. 筛选当前需要处理的文件
    train_files = filter_file_list(train_files_all, target_arch, target_opt)
    test_files = filter_file_list(test_files_all, target_arch, target_opt)
    valid_files = filter_file_list(valid_files_all, target_arch, target_opt)

    print(f"    Filtered Files -> Train: {len(train_files)} | Test: {len(test_files)} | Valid: {len(valid_files)}")

    # 释放大列表内存
    del train_files_all, valid_files_all, test_files_all
    gc.collect()

    if len(train_files) == 0 and len(test_files) == 0 and len(valid_files) == 0:
        print("    No files found for this configuration. Skipping.")
        return

    # 3. 初始化当前 Batch 的去重集合
    existed_function_name = []
    existed_function_body = []

    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    # 4. 依次处理并保存
    # Train
    if train_files:
        train_data = process_file_list(train_files, input_dir, existed_function_name, existed_function_body,
                                       is_training_mode=True)
        save_json(train_data, os.path.join(output_dir, f'train_set_{prefix_name}.json'))
        del train_data  # 释放内存
        gc.collect()

    # Test
    if test_files:
        test_data = process_file_list(test_files, input_dir, existed_function_name, existed_function_body,
                                      is_training_mode=False)
        save_json(test_data, os.path.join(output_dir, f'test_set_{prefix_name}.json'))
        del test_data
        gc.collect()

    # Valid
    if valid_files:
        valid_data = process_file_list(valid_files, input_dir, existed_function_name, existed_function_body,
                                       is_training_mode=False)
        save_json(valid_data, os.path.join(output_dir, f'validation_set_{prefix_name}.json'))
        del valid_data
        gc.collect()

    print(f"[+] Completed: {prefix_name}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input_dir', type=str, required=True)
    parser.add_argument('-o', '--output_dir', type=str, required=True)
    parser.add_argument('--train_list', type=str, required=True)
    parser.add_argument('--valid_list', type=str, required=True)
    parser.add_argument('--test_list', type=str, required=True)

    # 新增参数
    parser.add_argument('--arch', type=str, required=True, help='Architecture (e.g., arm)')
    parser.add_argument('--opt', type=str, required=True, help='Optimization level (e.g., O0)')

    args = parser.parse_args()
    main(args)