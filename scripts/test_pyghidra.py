import pyghidra

pyghidra.start() # 确保在一开始就启动，否则后续的ghidra包识别不到

import os
import shutil
from ghidra.program.model.address import Address
from ghidra.program.database.symbol import VariableSymbolDB
from typing import Dict, Optional
from ghidra.program.model.listing import ParameterImpl, Program, StackFrame, Variable, ReturnParameterImpl, Function
from ghidra.program.model.symbol import SourceType

from ghidra.app.decompiler import DecompInterface, DecompileResults
from ghidra.program.model.data import StructureDataType, PointerDataType, CharDataType, IntegerDataType, \
    FunctionDefinitionDataType, FunctionDefinition, ParameterDefinitionImpl, VoidDataType
from ghidra.program.database.function import FunctionDB
from ghidra.program.model.pcode import HighFunction, HighSymbol, Varnode, HighFunctionDBUtil
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.base.project import GhidraProject
from ghidra.util.task import TaskMonitor
# from java.io import File

so_path = '/root/code/hackaday-u/session-one/exercises/c1'
so_path_stripped = '/root/code/hackaday-u/session-one/exercises/c1.stripped'
so_path_complicate = '/root/code/hackaday-u/session-one/exercises/test'
# so_path_complicate_stripped = '/root/code/hackaday-u/session-one/exercises/test.stripped'
so_path_complicate_stripped = r'D:\document\android-reverse\libs\libsentencepiece.so'

# # 采用这种方式不会动态链接
# project = GhidraProject.createProject("/tmp/ghidra_project", "TempProject", False)
# program = project.importProgram(File(so_path))
#
# flat_api = FlatProgramAPI(program)

def update_func_by_decomp(function: FunctionDB, calling_convention: str, high_func: HighFunction, program: Program):
    # note 可以通过如下的方式直接得到反编译分析的函数的参数和返回值分析结果（通过getStorage可以获得存储位置，可用于汇编代码）
    proto = high_func.getFunctionPrototype()
    return_type = proto.getReturnType()
    return_storage = proto.getReturnStorage() # 这也是关键（包括params部分的getStorage()，通过次可以实现让反编译的结果更新汇编内容，特别是栈变量/寄存器变量等）
    param_count = proto.getNumParams()
    # 参数
    params = [ParameterImpl(proto.getParam(i).getName(), proto.getParam(i).getDataType(), proto.getParam(i).getStorage(), program) for i in range(param_count)]

    # 返回变量
    return_var =  ReturnParameterImpl(return_type, return_storage, True, program)

    function.updateFunction(
        calling_convention,
        return_var,
        Function.FunctionUpdateType.CUSTOM_STORAGE,
        True,
        SourceType.USER_DEFINED,
        params,
    )


def search_local_by_name(name: str, stack_frame: StackFrame) -> Optional[Variable]:
    for var in stack_frame.getLocals():
        if var.getName() == name:
            return var

    return None


def analyze(path: str):
    try:
        # 打开一个项目，这种方式会自动保存（目前也没有其他更好的方法，不使用上下文管理器方式会导致libc.so中的函数无法被识别）
        with pyghidra.open_program(path, project_location="/tmp/ghidra_project/TempProject", project_name="TempProject", analyze=False) as flat_api:
            # 分析程序（包括反汇编）
            program = flat_api.getCurrentProgram()
            flat_api.analyzeAll(program)

            flat_api.analysis_propertes()

            # 获取DataTypeManager
            dtm = program.getDataTypeManager()

            char_ptr_ptr = PointerDataType(PointerDataType(CharDataType()))
            int_type = IntegerDataType()

            function_manager = program.getFunctionManager()
            # 获取目标函数
            func_name = 'main'
            function: Function = None # 默认时Fucntion
            for func in function_manager.getFunctions(True):
                if func.getName() == func_name:
                    function = func
                    break

            # 先进行反编译将反编译的结果与Listing内容同步
            print("利用decomp更新前的函数签名：", function.getSignature())
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            decomp_result = decompiler.decompileFunction(function, 60, TaskMonitor.DUMMY)
            print(decomp_result.getDecompiledFunction().getC())
            update_func_by_decomp(function, "__stdcall", decomp_result.getHighFunction(), program) # 通常，设置了正确的调用惯例之后就能识别出大致的函数签名（虽然类型可能不一定正确，但是至少要在参数数量上一般都能正确）
            print("利用decomp更新后的函数签名：", function.getParameters())

            # update_asm_by_high_func(function, decomp_result.getHighFunction(), program) # 注意一定要提前进行更新

            # #### 更改函数签名（参数名称与类型、返回值类型）：1.可以从HighFunction更改，但是HighFunction无法更改函数返回值和函数名称，此时需要从function更改；2.直接从function更改
            print(function.getParameters())
            local_map = decomp_result.getHighFunction().getLocalSymbolMap().getNameToSymbolMap()
            HighFunctionDBUtil.updateDBVariable(local_map['param_1'], "argc", IntegerDataType(), SourceType.USER_DEFINED)
            HighFunctionDBUtil.updateDBVariable(local_map['param_2'], "argv", PointerDataType(PointerDataType(CharDataType())), SourceType.USER_DEFINED)
            # # 当然也可以使用function更改
            # parameters = function.getParameters()
            # parameters[0].setDataType(int_type, SourceType.USER_DEFINED)
            # parameters[0].setName("argc", SourceType.USER_DEFINED)
            # parameters[1].setDataType(char_ptr_ptr, SourceType.USER_DEFINED)
            # parameters[1].setName("argv", SourceType.USER_DEFINED)
            function.setReturnType(int_type, SourceType.USER_DEFINED)
            decomp_result = decompiler.decompileFunction(function, 60, TaskMonitor.DUMMY)
            print("更改完函数签名后：")
            print(decomp_result.getDecompiledFunction().getC())

            #### 更改局部变量
            ### 需要将汇编代码和反编译代码进行匹配，将汇编代码中对应的局部变量进行重命名与更改，并间接更新反编译结果（不能保证对某个变量的修改一定能在反编译的结果中表现出来

            # ## 直接做法：利用HighFunctionDBUtil修改HighSymbol的名称和类型
            # local_map: Dict[str, HighSymbol] = dict(decomp_result.getHighFunction().getLocalSymbolMap().getNameToSymbolMap())
            # print(local_map)
            # tx = program.startTransaction("begin")
            # # local_map['a'].getSymbol().setName("new_a", SourceType.USER_DEFINED)
            # HighFunctionDBUtil.updateDBVariable(local_map['a'], "stack_a", IntegerDataType(), SourceType.USER_DEFINED)
            # HighFunctionDBUtil.updateDBVariable(local_map['b'], "stack_b", IntegerDataType(), SourceType.USER_DEFINED)
            # HighFunctionDBUtil.updateDBVariable(local_map['iVar1'], "a", IntegerDataType(), SourceType.USER_DEFINED)
            # HighFunctionDBUtil.updateDBVariable(local_map['iVar2'], "b", IntegerDataType(), SourceType.USER_DEFINED)
            # # program.save("", TaskMonitor.DUMMY)
            # program.endTransaction(tx, True)
            # decomp_result = decompiler.decompileFunction(function, 60, TaskMonitor.DUMMY) # 只有再次进行反编译，当初更新的才能被同步进来
            # print(decomp_result.getHighFunction().getLocalSymbolMap().getNameToSymbolMap())
            # print(decomp_result.getDecompiledFunction().getC())

            # ## 间接做法：修改function的局部变量
            stack_frame = function.getStackFrame() # 获取栈帧，因为局部变量通常在栈帧中存放
            print(stack_frame.getLocals(), function.getLocalVariables()) # 获取所有的局部变量（不包含参数），这是两种等价写法
            # print(stack_frame.getParameters()) # 获取所有从栈上传递的参数（对于从寄存器上传递的参数，不会出现在其中）
            # print(function.getParameters()) # 获取参数（不管是通过栈传递还是通过寄存器传递），所以比stack_frame.getParameters()包含的更全
            # print(function.getAllVariables()) # 获取所有参数（不管参数是通过栈还是寄存器传递）和局部变量
            # # function.getVariables() # 满足指定条件的变量
            # local_10 = function.getVariables(lambda x : x.getName() == "local_10")[0]
            # local_10.setDataType(PointerDataType(CharDataType()), SourceType.USER_DEFINED)
            # local_10.setName("password", SourceType.USER_DEFINED)
            # local_1c = function.getVariables(lambda x : x.getName() == "local_1c")[0]
            # local_1c.setDataType(IntegerDataType(), SourceType.USER_DEFINED)
            # local_1c.setName("stack_argc", SourceType.USER_DEFINED)
            # local_28 = function.getVariables(lambda x : x.getName() == "local_28")[0]
            # local_28.setDataType(PointerDataType(PointerDataType(CharDataType())), SourceType.USER_DEFINED)
            # local_28.setName("stack_argv", SourceType.USER_DEFINED)
            # decomp_result = decompiler.decompileFunction(function, 60, TaskMonitor.DUMMY)
            # print("修改局部变量后发现也可能产生干扰，如下是更改了local_10，local_1c，local_28之后的结果：")
            # print(decomp_result.getDecompiledFunction().getC())
            # ## note 可以利用Parser来直接操纵反编译的结果（但是无法将更新同步回汇编结果，适合于最终进行局部变量名替换）
    finally:
        shutil.rmtree("/tmp/ghidra_project/TempProject")


def analyze_stripped(path: str):
    try:
        with pyghidra.open_program(path, project_location=r"D:\tmp\ghidra_project\TempProject", project_name="TempProject", analyze=True) as flat_api:
            program = flat_api.getCurrentProgram()
            # flat_api.analyzeAll(program)
            dtm = program.getDataTypeManager()
            function_manager = program.getFunctionManager()

            # 设置默认的起始地址为0
            new_base_addr = flat_api.toAddr(0x0)
            program.setImageBase(new_base_addr, True)


            # 获取默认地址空间，对于strip之后的二进制，不能根据函数名定位方法了，而是根据offset定位
            address_space = program.getAddressFactory().getDefaultAddressSpace()
            function = function_manager.getFunctionAt(address_space.getAddress(0x1127bc))

            # 打印汇编指令
            for inst in program.getListing().getInstructions(function.getBody(), True):
                print(inst.getAddress(), inst) # 打印对应的指令及地址

            # # 确定函数参数所存放的位置：
            # param_0 = function.getParameter(0)
            # if param_0.isRegisterVariable():
            #     print(param_0.getRegister()) # 对于单个存储单元唯一，如果一个参数是存放在多个寄存器或其他位置的（compound），则返回第一个
            # elif param_0.isStaticVariable():
            #     print(param_0.getStackOffset())


            # 先进行反编译将反编译的结果与Listing内容同步 update Listing via Decomp
            print("利用decomp更新前的函数签名：", function.getSignature())
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            decomp_result = decompiler.decompileFunction(function, 60, TaskMonitor.DUMMY)
            print(decomp_result.getDecompiledFunction().getC())
            update_func_by_decomp(function, "__stdcall", decomp_result.getHighFunction(), program) # 通常，设置了正确的调用惯例之后就能识别出大致的函数签名（虽然类型可能不一定正确，但是至少要在参数数量上一般都能正确）
            print("利用decomp更新后的函数签名：", function.getSignature())

            # # 更新函数签名 update Listing
            # # function.setName("main", SourceType.USER_DEFINED)
            # function.setReturnType(IntegerDataType(), SourceType.USER_DEFINED)
            # function.getParameter(0).setName("argc", SourceType.USER_DEFINED)
            # function.getParameter(1).setName("argv", SourceType.USER_DEFINED)
            # function.getParameter(1).setDataType(PointerDataType(PointerDataType(CharDataType())), SourceType.USER_DEFINED)

            # tx = program.startTransaction("begin")
            local_map = decomp_result.getHighFunction().getLocalSymbolMap().getNameToSymbolMap()
            HighFunctionDBUtil.updateDBVariable(local_map['param_1'], "argc", IntegerDataType(), SourceType.USER_DEFINED)
            HighFunctionDBUtil.updateDBVariable(local_map['param_2'], "argv", PointerDataType(PointerDataType(CharDataType())), SourceType.USER_DEFINED)
            decomp_result.getHighFunction().getFunction().setReturnType(IntegerDataType(), SourceType.USER_DEFINED)
            decomp_result.getHighFunction().getFunction().setName("main", SourceType.USER_DEFINED)
            # program.endTransaction(tx, True)
            # program.save("", TaskMonitor.DUMMY)
            # # update Decomp via Listing
            print("更新签名后：", function.getSignature())
            # 更新局部变量
            HighFunctionDBUtil.updateDBVariable(local_map['iVar1'], "a", IntegerDataType(), SourceType.USER_DEFINED)
            HighFunctionDBUtil.updateDBVariable(local_map['iVar2'], "b", IntegerDataType(), SourceType.USER_DEFINED)

            decomp_result = decompiler.decompileFunction(function, 60, TaskMonitor.DUMMY)
            print(decomp_result.getDecompiledFunction().getC())
            print(function.getLocalVariables(), function.getParameters())



    finally:
        shutil.rmtree(r"D:\tmp\ghidra_project\TempProject")

# analyze(so_path)
# analyze_stripped(so_path_stripped)
# analyze(so_path_complicate)
analyze_stripped(so_path_complicate_stripped)