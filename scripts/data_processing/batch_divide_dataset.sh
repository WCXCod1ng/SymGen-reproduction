#!/bin/bash

# ================= 配置区域 =================
# Python 脚本路径
SCRIPT_PATH="divide_dataset_adjust.py"

# 输入输出路径
INPUT_DIR="/root/code/SymGen/all_dataset"     # 原始数据集根目录
OUTPUT_DIR="/root/code/SymGen/dataset_divided/data"     # 处理结果输出目录

# 划分列表文件路径
TRAIN_LIST="/root/code/SymGen/dataset_divided/index_file/train.json"
VALID_LIST="/root/code/SymGen/dataset_divided/index_file/valid.json"
TEST_LIST="/root/code/SymGen/dataset_divided/index_file/test.json"

# 架构和优化等级定义
#ARCHS=("arm_32" "mips_32" "x86_32" "x86_64")
ARCHS=("mips_32" "x86_32" "x86_64")
OPTS=("O0" "O1" "O2" "O3")
#OPTS=("O2" "O3")
# ===========================================

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

echo "========================================"
echo "开始批量处理数据..."
echo "Input Dir: $INPUT_DIR"
echo "Output Dir: $OUTPUT_DIR"
echo "========================================"

for arch in "${ARCHS[@]}"; do
    for opt in "${OPTS[@]}"; do

        echo ""
        echo ">>> 正在处理: 架构 [${arch}] - 优化等级 [${opt}]"

        python3 "$SCRIPT_PATH" \
            --input_dir "$INPUT_DIR" \
            --output_dir "$OUTPUT_DIR" \
            --train_list "$TRAIN_LIST" \
            --valid_list "$VALID_LIST" \
            --test_list "$TEST_LIST" \
            --arch "${arch}" \
            --opt "${opt}"

        # 检查上一个命令的退出状态
        if [ $? -ne 0 ]; then
            echo "[!] 错误: 处理 ${arch}/${opt} 失败！"
            # 这里的 exit 1 可以去掉，如果你希望即使出错也继续处理下一个
            # exit 1
        else
            echo "[√] 完成: ${arch}/${opt}"
        fi

    done
done

echo ""
echo "========================================"
echo "所有任务处理完毕。"
echo "========================================"