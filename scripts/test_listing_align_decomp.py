import pyghidra
pyghidra.start()

from ghidra.app.decompiler import DecompInterface, ClangToken
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.decompiler import ClangFunction, ClangStatement, ClangTokenGroup

def find_indirect_calls_in_func(flat_api, start_offset):
    """
    分析指定函数中的 ARM64 间接调用
    """

    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    func_manager = program.getFunctionManager()

    # 设置默认的起始地址为0
    new_base_addr = flat_api.toAddr(0x0)
    program.setImageBase(new_base_addr, True)

    image_base = program.getImageBase()

    func_addr = image_base.add(start_offset)
    func = func_manager.getFunctionAt(func_addr)
    if not func:
        print(f"找不到起始地址为 0x{start_offset:X} 的函数")
        return None

    print(f"分析函数: {func.getName()} @ 0x{start_offset:X}")

    # 初始化反编译接口
    decomp = DecompInterface()
    decomp.openProgram(program)
    res = decomp.decompileFunction(func, 60, None)
    high_func = res.getHighFunction()
    if not high_func:
        print(f"反编译失败: {func.getName()}")
        return None

    clang_root = res.getCCodeMarkup()

    lines = res.getDecompiledFunction().getC().split("\n")

    indirect_calls = []

    # 遍历 PcodeOps 找 CALLIND
    for op in high_func.getPcodeOps():
        if op.getOpcode() == PcodeOp.CALLIND:
            begin_addr = op.getSeqnum().getTarget()
            instr = listing.getInstructionAt(begin_addr)
            next_instr = instr.getNext()
            if not instr or not next_instr:
                continue
            end_addr = next_instr.getMinAddress()

            # begin_expr = search_begin(clang_root, begin_addr)
            # end_expr = search_begin(clang_root, end_addr)
            # # expr = "aaa"
            # expr = "no"
            # begin_idx = get_idx(lines, begin_expr)
            # end_idx = get_idx(lines, end_expr)
            # if begin_idx != -1 and end_idx != -1:
            #     expr = lines[begin_idx: end_idx]

            # 创建用户指定的地址范围
            user_addr_set = program.getAddressFactory().getAddressSet(begin_addr, end_addr.previous())

            # 5. 遍历ClangToken并提取与范围匹配的代码
            expr = []
            for token in clang_root:
                token_addr_min = token.getMinAddress()
                token_addr_max = token.getMaxAddress()

                if token_addr_min is not None and token_addr_max is not None:
                    # 创建当前token的地址范围
                    token_addr_set = program.getAddressFactory().getAddressSet(token_addr_min, token_addr_max)

                    # 6. 检查地址范围是否有交集
                    if user_addr_set.intersects(token_addr_set):
                        expr.append(token.toString())

            begin_offset = begin_addr.subtract(image_base)
            indirect_calls.append((begin_addr, begin_offset, str(instr), expr))

    # 按偏移排序
    indirect_calls.sort(key=lambda x: x[0])

    if not indirect_calls:
        return None

    print(lines[1])
    return indirect_calls

def get_idx(lines, exprs):
    idx = -1
    n = len(exprs)
    for i in range(len(exprs)-n+1):
        found = True
        for e in exprs:
            if lines[i].find(e) == -1:
                found = False
        if found:
            idx = i
            break
    return idx

def search_begin(clang_node, start_addr):
    """
    在 AST 中收集指定地址范围内的反编译源码
    """
    lines = []


    min_a = clang_node.getMinAddress()
    if start_addr == min_a:
        # 只在语句节点时收集完整文本
        if isinstance(clang_node, ClangTokenGroup):
            lines.append(clang_node.toString())

        for i in range(clang_node.numChildren()):
            lines.extend(
                search_begin(clang_node.Child(i), start_addr)
            )
    return lines


# # 递归查找：给定 target addr（调用指令地址），在 clang 节点树中找到最先匹配到的节点并返回其文本
# def find_expr_for_address(node, target_addr) -> str:
#     """
#     尽量返回最合适的表达式文本（node.toString()）
#     使用鸭子类型（getMinAddress, numChildren, Child）
#     """
#     res = ""
#     try:
#         # 有些节点有 getMinAddress 或 getMaxAddress 方法
#         node_addr = None
#         if hasattr(node, "getMinAddress"):
#             node_addr = node.getMinAddress()
#             if node_addr is not None and node_addr == target_addr:
#                 # 找到节点直接返回文本
#                 try:
#                     res += node.toString() + "\n"
#                 except Exception:
#                     # fallback: try token-based
#                     pass
#     except Exception:
#         node_addr = None
#
#     # 递归子节点（如果有）
#     try:
#         nchild = node.numChildren()
#     except Exception:
#         nchild = 0
#
#     for i in range(nchild):
#         try:
#             child = node.Child(i)
#         except Exception:
#             continue
#         res += find_expr_for_address(child, target_addr)
#
#     return res


if __name__ == "__main__":
    so_file_path = r"D:\document\android-reverse\dataset\sgtpuzzles\app\build\outputs\apk\release\app-release\lib\arm64-v8a\libpuzzles.so"
    project_path = r"D:\tmp\ghidra_project\TempProject"
    project_name = "TempProject2"

    start_offset_hex = "0x00094528"
    start_offset = int(start_offset_hex, 16)

    with pyghidra.open_program(so_file_path,
                               project_location=project_path,
                               project_name=project_name,
                               analyze=True) as flat_api:
        func = flat_api.getFirstFunction()
        while func:
            if func.getEntryPoint().getOffset() < start_offset:
                func = flat_api.getFunctionAfter(func)
                continue
            indirect_calls = find_indirect_calls_in_func(flat_api, func.getEntryPoint().getOffset())
            if indirect_calls:
                for addr, offset, instr_str, expr in indirect_calls:
                    print(f"{addr} 偏移: 0x{offset:X} | 指令: {instr_str} | 表达式: {expr}")
                print("==========================")
            func = flat_api.getFunctionAfter(func)
