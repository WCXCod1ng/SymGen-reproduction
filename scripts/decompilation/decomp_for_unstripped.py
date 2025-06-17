import os
import json
from ghidra.app.decompiler import DecompInterface # Ghidra提供的类，用于将二进制反编译为类似于C语言的代码
from ghidra.util.task import ConsoleTaskMonitor # 跟踪反编译进度
from ghidra.ghidra_builtins import *

file_path = str(getProgramFile()) # 获取Ghidra中加载的二进制文件的路径，也就是将来在执行analyzedHeadless命令时import的二进制文件
print("1. load the binary file: ", file_path)
output_dir = r"D:\document\python\research\SymGen-reproduction\decompiled\unstripped"
assert (
    output_dir
), "Please provide the dir to save the results in 'decompilation/decom_for_unstripped.py'"
output_file_path = os.path.join(output_dir, file_path.split('/')[-1] + '.json')


if not os.path.exists(output_dir):
    print("2. create the output folder: ", output_dir)
    os.makedirs(output_dir)

def get_data_type_info(f, var, is_arg, count):
    # variable name and type
    varname = var.getName()
    type_object = var.getDataType()
    type_name = type_object.getName()

    # get to what ever the pointer is pointing to
    ptr_bool = False
    for _ in range(type_name.count('*')): # 处理指针类所指向的基础类型，注意int** -> int
        type_object = type_object.getDataType()
        type_name = type_object.getName()
        ptr_bool = True

    # if a typedef, get the primitive type definition
    try:
        type_object = type_object.getBaseDataType() # 处理typedef类型，获取其基本类型
        type_name = type_object.getName()
    except:
        pass

    # find if struct, union, enum, or none of the above
    is_struct = False
    is_union = False
    if len(str(type_object).split('\n')) >= 2:
        if 'Struct' in str(type_object).split('\n')[2]:
            is_struct = True
        elif 'Union' in str(type_object).split('\n')[2]:
            is_union = True

    try:
        type_object.getCount()
        is_enum = True
    except:
        is_enum = False

    if ptr_bool:
        type_name += ' *' # 为指针类型添加后缀（但是这里为什么只添加了一次，没有考虑多重指针？）

    f[varname] = {'type': str(type_name), 'addresses': [],
                  'agg': {'is_enum': is_enum, 'is_struct': is_struct, 'is_union': is_union}} # 收集变量的元信息并存储到字典f中

    locs = ref.getReferencesTo(var) # 使用Ghidra的引用管理器获取变量var的所有引用
    for loc in locs: # 遍历这些引用，将每个引用地址转换为字符串并添加到addresses列表
        f[varname]['addresses'].append(loc.getFromAddress().toString())

    if is_arg: # 对于参数，可能是由寄存器传递的，需要获取其寄存器名称
        # need to store the register the args are saved into.
        f[varname]['register'] = var.getRegister().getName()
        f[varname]['count'] = count

    return f


getCurrentProgram().setImageBase(toAddr(0), 0) # 将程序的映像基址设置为 0（可能是为了简化地址计算，常见于分析 ELF 文件）
ref = currentProgram.getReferenceManager() # 获取引用管理器，用于跟踪变量和函数的引用
currentProgram = getCurrentProgram() # 当前加载的程序对象
listing = currentProgram.getListing() # 获取代码单元列表（即Ghidra中的Listing View中展示的汇编指令）
function = getFirstFunction() # 获取程序中的第一个函数

ifc = DecompInterface()
ifc.openProgram(currentProgram)

res = {}


print("3. decompile function: ")
while function is not None:
    print('\t', function.name)
    funcname = function.name # 函数名
    addrSet = function.getBody() # 函数代码段（一个地址范围）
    codeUnits = listing.getCodeUnits(addrSet, True) # 根据地址返回拿到汇编指令（True表示正向遍历）

    all_vars = function.getAllVariables() # 获取所有的变量（包括栈变量和寄存器变量）和参数
    all_args = function.getParameters()

    assembly = []

    for codeUnit in codeUnits: # 将每一条指令添加到汇编列表中
        instruction = codeUnit.toString()
        assembly.append(instruction)
    
    # regular stack vars
    var_metadata = {}
    for var in all_vars:
        var_metadata = get_data_type_info(var_metadata, var, False, -1) # 获取每个变量的基本信息，count=-1表示无需计数

    # function args
    args_metadata = {}
    for arg in all_args:
        count = 0
        if arg.getRegister() is not None:
            args_metadata = get_data_type_info(args_metadata, arg, True, count) # 获取每个寄存器传参的基本信息，count用于编号参数，只考虑寄存器传递的参数
            count += 1

    decomp = ifc.decompileFunction(function, 60, ConsoleTaskMonitor()) # 反编译
    decompiled_function = decomp.getDecompiledFunction().getC()

    res[funcname] = {
        "assembly": assembly, # 汇编指令列表
        "decomp_code": decompiled_function, # 反编译之后的C代码
        "variable_metadata": var_metadata, # 栈变量元信息
        "args_metadata": args_metadata, # 参数元信息
        'function_address': {
            'start': str(function.getEntryPoint()),
            'end': str(function.getBody().getMaxAddress()),
        }
    }

    function = getFunctionAfter(function) # 获取下一个参数，继续循环

with open(output_file_path, 'w') as f:
    print("4. write result to output_file_path: ", output_file_path)
    json.dump(res, f, indent=4)
