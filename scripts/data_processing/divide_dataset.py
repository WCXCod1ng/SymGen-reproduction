import sys
import json
import os
import random
import argparse

from antlr4 import *
from antlr.CLexer import CLexer
from antlr.CParser import CParser
from antlr.CVisitor import CVisitor


lines = []
column_offset = {}

function_map = {}
function_count = 0


class SubstituteFunctionNameVisitor(CVisitor):
    ### Substitute address related constant
    # def visitPrimaryExpression(self, ctx:CParser.PrimaryExpressionContext):
    #     if ctx.Constant() is not None:
    #         constant_token = ctx.Constant().getSymbol()
    #         if constant_token.text.startswith('0x'):
    #             lines[constant_token.line - 1] = lines[constant_token.line - 1][0: constant_token.column + column_offset[constant_token.line - 1]] + '[Magic Number]' + lines[constant_token.line - 1][constant_token.column + len(constant_token.text) + column_offset[constant_token.line - 1]:]
    #             column_offset[constant_token.line - 1] += len('[Magic Number]') - (len(constant_token.text))
    #     return self.visitChildren(ctx)
    
    ### Substitute address related function name
    def visitPostfixExpression(self, ctx:CParser.PostfixExpressionContext):
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
                    lines[functionNameToken.line - 1] = lines[functionNameToken.line - 1][0: functionNameToken.column + column_offset[functionNameToken.line - 1]] + new_function_name + lines[functionNameToken.line - 1][functionNameToken.column + len(functionNameToken.text) + column_offset[functionNameToken.line - 1]:]
                    column_offset[functionNameToken.line - 1] += len(new_function_name) - (len(functionNameToken.text))
        return self.visitChildren(ctx)


def substitute_decompiled(code):
    global lines
    global column_offset
    global function_map
    global function_count

    file = open('code.txt', 'w')
    file.write(code)
    file.close()

    file = open('code.txt', 'r')
    code = file.read()
    antlrInput = InputStream(code)
    file.close()

    file = open('code.txt', 'r')
    lines = file.readlines()
    file.close()

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

    res = ""
    for line in lines:
        res += line

    os.remove('code.txt')

    return res


def main(args):
    input_dir = args.input_dir
    output_dir = args.output_dir

    ### Divide Binary
    train_part = 0.8
    test_part = 0.1
    validation_part = 0.1

    binary_names = []
    path_map = {}
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            binary_names.append(file)
            path_map[file] = os.path.join(root, file)
    
    random.shuffle(binary_names)
    train_binary = binary_names[0: int(train_part * len(binary_names))]
    test_binary = binary_names[int(train_part * len(binary_names)): int((train_part + test_part) * len(binary_names))]
    validation_binary = binary_names[int((train_part + test_part) * len(binary_names)): ]

    ### save the division
    # with open('/process_data/division_binary.json', 'w') as f:
    #     data = {}
    #     data['train_binary'] = train_binary
    #     data['test_binary'] = test_binary
    #     data['validation_binary'] = validation_binary
    #     json.dump(data, f, indent=4)

    ### use the saved division
    # with open('/process_data/division_binary.json', 'r') as f:
    #     data = json.load(f)
    #     train_binary = data['train_binary']
    #     test_binary = data['test_binary']
    #     validation_binary = data['validation_binary']


    print("[+] Training Set", train_binary)
    print("[+] Test Set", test_binary)
    print("[+] Validation Set", validation_binary)


    existed_function_name = []
    existed_function_body = []
    train = []
    test = []
    validation = []

    print("[+] Process Training Set Binary")
    for binary in train_binary:
        with open(path_map[binary]) as f:
            data = json.load(f)

        for function_name in data.keys():
            ### remove meaningless like 'FUN_00000f70' in training set
            if 'FUN_' in function_name:
                continue

            ### delete duplicate name
            if function_name in existed_function_name:
                continue
            existed_function_name.append(function_name)

            decompiled_code = data[function_name]['unstripped']
            if decompiled_code is None:
                continue

            modified_decompiled_code = substitute_decompiled(data[function_name]['stripped'])
            ### delete duplicate func content
            if modified_decompiled_code in existed_function_body:
                continue
            existed_function_body.append(modified_decompiled_code)
            
            sample = {}
            sample["instruction"] = "Suppose you are an expert in software reverse engineering. Here is a piece of decompiled code, you should infer code semantics and tell me the original function name from the contents of the function to replace [MASK]. Now the decompiled codes are as follows:"
            sample["input"] = decompiled_code
            sample["output"] = 'The predicted function name is ' + function_name
            train.append(sample)


    print("[+] Process Test Set Binary")
    for binary in test_binary:
        with open(path_map[binary]) as f:
            data = json.load(f)

        for function_name in data.keys():
            ### remove meaningless like 'FUN_00000f70'
            if 'FUN_' in function_name:
                continue

            ### delete duplicate name
            if function_name in existed_function_name:
                continue
            existed_function_name.append(function_name)

            decompiled_code = data[function_name]['stripped']
            if decompiled_code is None:
                continue

            modified_decompiled_code = substitute_decompiled(decompiled_code)
            ### delete duplicate func content
            if modified_decompiled_code in existed_function_body:
                continue
            existed_function_body.append(modified_decompiled_code)

            sample = {}
            sample["instruction"] = "Suppose you are an expert in software reverse engineering. Here is a piece of decompiled code, you should infer code semantics and tell me the original function name from the contents of the function to replace [MASK]. Now the decompiled codes are as follows:"
            sample["input"] = decompiled_code
            sample["output"] = 'The predicted function name is ' + function_name
            test.append(sample)


    print("[+] Process Valiation Set Binary")
    for binary in validation_binary:
        with open(path_map[binary]) as f:
            data = json.load(f)

        for function_name in data.keys():
            ### remove meaningless like 'FUN_00000f70'
            if 'FUN_' in function_name:
                continue

            ### delete duplicate name
            if function_name in existed_function_name:
                continue
            existed_function_name.append(function_name)
            
            decompiled_code = data[function_name]['stripped']
            if decompiled_code is None:
                continue

            modified_decompiled_code = substitute_decompiled(decompiled_code)
            ### delete duplicate func content
            if modified_decompiled_code in existed_function_body:
                continue
            existed_function_body.append(modified_decompiled_code)
            
            sample = {}
            sample["instruction"] = "Suppose you are an expert in software reverse engineering. Here is a piece of decompiled code, you should infer code semantics and tell me the original function name from the contents of the function to replace [MASK]. Now the decompiled codes are as follows:"
            sample["input"] = decompiled_code
            sample["output"] = 'The predicted function name is ' + function_name
            validation.append(sample)


    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, 'training_set.json'), 'w') as f:
        json.dump(train, f, indent=4)
        print("[+] Save training set to", os.path.join(output_dir, 'train_set.json'))
    with open(os.path.join(output_dir, 'test_set.json'), 'w') as f:
        json.dump(test, f, indent=4)
        print("[+] Save test set to", os.path.join(output_dir, 'test_set.json'))
    with open(os.path.join(output_dir, 'validation_set.json'), 'w') as f:
        json.dump(validation, f, indent=4)
        print("[+] Save validation set to", os.path.join(output_dir, 'validation_set.json'))



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Divide data into training, test and validation set.')
    parser.add_argument('-i', '--input_dir', type=str, required=True,
        # default='',
        help='Directory containing the combined decompiled code.')
    parser.add_argument('-o', '--output_dir', type=str, required=True,
        # default='',
        help='Directory to save the divided dataset.')
    args = parser.parse_args()

    main(args)
