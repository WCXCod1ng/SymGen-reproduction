import os.path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import threading
import time
import pandas as pd
import glob
import subprocess
import argparse
import json
import sys


thread_num = 10
executor = ThreadPoolExecutor(max_workers=thread_num)
ghidra_projects = [f'parser_{i}/' for i in range(10)] # Ghidra的analyzeHeadless要求对于每个二进制文件使用单独的项目目录，而10个线程就需要10个目录


def process_unstripped_binary(ghidra_path, project_path, project_name, binary_path):
    print(f"[*] hold {project_name} for {binary_path}")
    cmd = f"{ghidra_path} {project_path} {project_name} -import {binary_path} -readOnly -postScript ./decompilation/decomp_for_unstripped.py"
    try:
        subprocess.run(cmd, shell=True, timeout=900*4)
    except subprocess.TimeoutExpired:
        print(f"[!] timeout for {binary_path}")
    ghidra_projects.append(project_name)
    print(f"[+] release {project_name} after finishing {binary_path}")


def process_stripped_binary(ghidra_path, project_path, project_name, binary_path):
    """
    :param ghidra_path: Ghidra的analyzeHeadless的可执行文件路径
    :param project_path: Ghidra的项目存储目录
    :param project_name: Ghidra项目名称，只要不同项目的名称不同即可
    :param binary_path: 要处理的二进制文件的路径（例如.so文件）
    """
    print(f"[*] hold {project_name} for {binary_path}")
    # cmd = f"{ghidra_path} {project_path} {project_name} -import {binary_path} -readOnly -postScript ./decompilation/decomp_for_stripped.py" # 使用Ghidra命令，并在Ghidra反编译之后运行decomp_for_unstripped.py处理。多次执行时可以的，不同的二进制文件分别以一个文件单元的形式存在，Ghidra会根据导入的二进制文件路径（binary_path）区分不同的文件单元（只要binary_path不同就不会覆盖，建议使用绝对路径）。如果想要分析之后不保存，则可以考虑使用-deleteProject选项
    cmd = f"{ghidra_path} {project_path} {project_name} -import {binary_path} -readOnly -postScript .\decompilation\decomp_for_stripped.py" # 使用Ghidra命令，并在Ghidra反编译之后运行decomp_for_unstripped.py处理。多次执行时可以的，不同的二进制文件分别以一个文件单元的形式存在，Ghidra会根据导入的二进制文件路径（binary_path）区分不同的文件单元（只要binary_path不同就不会覆盖，建议使用绝对路径）。如果想要分析之后不保存，则可以考虑使用-deleteProject选项
    try:
        subprocess.run(cmd, shell=True, timeout=900*4)
    except subprocess.TimeoutExpired:
        print(f"[!] timeout for {binary_path}")
    ghidra_projects.append(project_name)
    print(f"[+] release {project_name} after finishing {binary_path}")


def main(args):
    binary_path = args.binary_path
    if os.path.isfile(binary_path):
        print(f"[+] start to process {binary_path}")
        while len(ghidra_projects) == 0: # 等待项目池有空闲的
            print("Wait for ghidra project: 1 sec")
            time.sleep(1)
        ghidra_project = ghidra_projects.pop() # 从项目池中提取一个
        executor.submit(process_unstripped_binary if args.unstripped else process_stripped_binary,
                        ghidra_path=args.ghidra_path,
                        project_path=args.project_path,
                        project_name=ghidra_project,
                        binary_path=binary_path,) # 启动一个线程执行任务
    elif os.path.isdir(binary_path):
        for root, dirs, files in os.walk(binary_path): # 处理所有二进制文件（也即传入的可以是一个文件夹）
            for file in files:
                binary_file_path = os.path.join(root, file)
                print(f"[+] start to process {binary_file_path}")
                while len(ghidra_projects) == 0:
                    print("Wait for ghidra project: 1 sec")
                    time.sleep(1)
                ghidra_project = ghidra_projects.pop()
                executor.submit(process_unstripped_binary if args.unstripped else process_stripped_binary,
                        ghidra_path=args.ghidra_path,
                        project_path=args.project_path,
                        project_name=ghidra_project,
                        # binary_path=binary_path,)
                        binary_path=binary_file_path,) # note 这里是否应当做如下更改
                while executor._work_queue.qsize() > thread_num:
                    print("Wait for executor: 1 sec", executor._work_queue.qsize())
                    time.sleep(1)
    else:
        print(f"Check your {binary_path}.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Perform parallel decompilation and disassembling for binaries')
    parser.add_argument('-u', '--unstripped', action='store_true',
        help="Indicates that the binary is unstripped (contains debug symbols).")
    parser.add_argument('-s', '--stripped', action='store_true',
        help="Indicates that the binary is stripped (lacks debug symbols).")
    parser.add_argument('-b', '--binary_path', type=str, required=True,
        # default='',
        help="Specify the path to the binary file or folder containing binaries.")
    parser.add_argument('-g', '--ghidra_path', type=str, required=True,
        # default='',
        help="Provide the path to the Ghidra 'analyzeHeadless'.")
    parser.add_argument('-p', '--project_path', type=str, required=True,
        # default='',
        help="Specify the directory path to Ghidra projects.")
    args = parser.parse_args()

    if args.unstripped == True and args.stripped == True or args.unstripped == False and args.stripped == False:
        print("Error! You can just choose one mode '-u' or '-s'")
        sys.exit(0)

    if not os.path.exists(args.project_path):
        os.makedirs(args.project_path)

    main(args)
