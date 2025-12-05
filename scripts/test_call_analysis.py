# 获取当前程序中所有函数的调用图信息
# @author Ghidra
# @category Analysis
# @keybinding
# @menupath
# @toolbar

import pyghidra
pyghidra.start()


from ghidra.program.model.symbol import ExternalManager
# 导入必要的Ghidra API类
from ghidra.util.task import ConsoleTaskMonitor


def get_function_call_graph(path: str):
    """
    分析当前程序，生成一个函数调用图。

    返回:
        dict: 一个字典，键是调用者函数的起始偏移量(int)，
              值是一个包含所有被调用函数起始偏移量的集合(set)。
    """
    call_graph = {}

    with pyghidra.open_program(path, project_location=r"D:\tmp\ghidra_project\TempProject", project_name="TempProject2",
                               analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()

        external_manager = program.getExternalManager()

        # 设置默认的起始地址为0
        new_base_addr = flat_api.toAddr(0x0)
        program.setImageBase(new_base_addr, True)

        # 获取函数管理器，用于访问程序中的所有函数
        function_manager = program.getFunctionManager()
        monitor = ConsoleTaskMonitor()

        # 获取当前主程序的文件名，用于标识内部调用
        main_program_name = program.getName()

        # getFunctions(True)返回一个可以遍历所有函数（按地址升序）的迭代器
        all_functions = function_manager.getFunctions(True)

        print("正在分析 {} 个函数...".format(function_manager.getFunctionCount()))

        for caller_function in all_functions:
            # 只有在当前主程序中定义的函数才作为调用者进行分析
            if caller_function.getProgram().getName() != main_program_name:
                continue

            caller_offset = caller_function.getEntryPoint().getOffset()

            # 为当前调用者函数初始化一个按库分类的被调用者字典
            callees_by_library = {}

            # 获取所有被调用的函数集合
            called_functions = caller_function.getCalledFunctions(monitor)

            for callee_function in called_functions:
                callee_offset = callee_function.getEntryPoint().getOffset()

                # # real_call_target = callee_function
                # # 检查被调用的函数是否是一个Thunk
                # if callee_function.isThunk():
                #     # 如果是Thunk，获取它真正指向的函数
                #     thunked_func = callee_function.getThunkedFunction(True)
                #
                #     # 现在，我们检查最终目标函数(final_destination_func)的属性
                #     # 而不是检查PLT存根(callee_function)的属性
                #     if thunked_func.isExternal():
                #         # 这是一个外部调用
                #         ext_loc = thunked_func.getExternalLocation()
                #         library_name = "UNKNOWN_EXTERNAL"  # 默认值
                #         if ext_loc is not None:
                #             lib_name_from_api = ext_loc.getLibraryName()
                #             if lib_name_from_api and external_manager.contains(lib_name_from_api):
                #                 library_name = lib_name_from_api
                # else:
                #     # 这是一个内部调用
                #     library_name = main_program_name
                # note 不考虑外部调用的具体信息，我们只想要内部调用（且不是thunk，因为thunk函数一般没有意义），注意在极端情况下会有导致遗漏自定义的函数
                if callee_function.isThunk() or callee_function.isExternal():
                    library_name = "EXTERNAL"
                else:
                    # library_name = main_program_name
                    library_name = "INTERNAL"

                # 使用 setdefault 来优雅地处理新库名的情况
                # 如果 library_name 不在字典中，会先设置一个空集合 a.setdefault(key, set())
                # 然后再添加元素 .add(element)
                callees_by_library.setdefault(library_name, set()).add(callee_offset)

            # 如果该函数有调用任何其他函数，则将其结果存入主调用图字典
            if callees_by_library:
                call_graph[caller_offset] = callees_by_library

        return call_graph


if __name__ == '__main__':
    # 执行函数并获取调用图
    function_calls = get_function_call_graph(path=r"D:\document\android-reverse\dataset\sgtpuzzles\app\build\outputs\apk\release\app-release\lib\arm64-v8a\libpuzzles.so")

    print("\n--- 函数调用图 (调用者 -> {库名 -> {被调用者偏移量,...}}) ---\n")

    # 为了方便查看，对结果进行排序和格式化打印
    for caller_offset in sorted(function_calls.keys()):
        print("{} ->".format(hex(caller_offset)))

        callees_by_lib = function_calls[caller_offset]
        # 排序库名以获得一致的输出
        for lib_name in sorted(callees_by_lib.keys()):
            offsets_set = callees_by_lib[lib_name]
            # 排序偏移量并格式化为十六进制字符串
            callees_str = ", ".join(hex(o) for o in sorted(list(offsets_set)))
            print("  - {}: {{{}}}".format(lib_name, callees_str))

    print("\n分析完成！共找到 {} 个发起调用的函数。".format(len(function_calls)))

    print("=======================check failed")
    cnt = 0
    # check
    for caller_offset in sorted(function_calls.keys()):
        callees_by_lib = function_calls[caller_offset]
        if "libpuzzles.so" in callees_by_lib:
            for offset in callees_by_lib['libpuzzles.so']:
                if offset > 0x137903:
                    cnt += 1
                    print("{}- {}: {{{}}}".format(caller_offset, lib_name, hex(offset)))
    print("{}个check failed".format(cnt))

