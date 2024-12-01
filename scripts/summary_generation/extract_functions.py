import os
import sys
from antlr4 import *
from antlr.CLexer import CLexer
from antlr.CParser import CParser
from antlr.CVisitor import CVisitor
import json
import argparse


sys.setrecursionlimit(10000)
d = {}
lines = []

class extractFunctionsVisitor(CVisitor):
    def visitFunctionDefinition(self, ctx:CParser.FunctionDefinitionContext):
        if ctx.declarator() is not None:
            if ctx.declarator().directDeclarator() is not None:
                if ctx.declarator().directDeclarator().directDeclarator() is not None:
                    functionNameCtx = ctx.declarator().directDeclarator().directDeclarator()
                    functionName = functionNameCtx.getText()

                    start = ctx.start
                    stop = ctx.stop

                    tmp = ""
                    for i in range(start.line - 1, stop.line):
                        tmp += lines[i] + ' '
                    
                    if 'main' not in tmp and '{' in tmp and '}' in tmp:
                        d[functionName] = tmp

        return self.visitChildren(ctx)


def process(source_dir, output_dir):
    global lines
    global d

    with open(os.path.join(output_dir, 'source_code_function.json'), 'w') as f:
        json.dump({}, f, indent=4)

    for root, dirs, files in os.walk(source_dir):
        for filename in files:
            if filename.endswith('.c'):
                print("[+] Processing " + os.path.join(root, filename))
                file = open(os.path.join(root, filename), 'r', encoding='latin-1')
                code = file.read()
                antlrInput = InputStream(code)
                file.close()

                file = open(os.path.join(root, filename), 'r', encoding='latin-1')
                lines = file.readlines()
                file.close()

                lexer = CLexer(antlrInput)
                stream = CommonTokenStream(lexer)
                parser = CParser(stream)
                tree = parser.compilationUnit()

                visitor = extractFunctionsVisitor()
                visitor.visit(tree)

                with open(os.path.join(output_dir, 'source_code_function.json'), 'r+') as f:
                    data = json.load(f)
                    for function_name in d.keys():
                        data[function_name] = d[function_name]
                    f.seek(0)
                    f.truncate()
                    json.dump(data, f, indent=4)

    print("[+] Save results with possible dupicates to", os.path.join(output_dir, 'source_code_function.json'))


def remove_duplicates(test_file, output_dir):
    with open(os.path.join(output_dir, 'source_code_function.json'), 'r') as f:
        source_functions = json.load(f)

    with open(test_file, 'r') as f:
        test_set = []
        for it in json.load(f):
            test_set.append(it['output'].split(' ')[-1]) ### get function name

    non_duplicated_source_functions = {}
    for function_name in source_functions.keys():
        if function_name in test_set:
            print(function_name)
            continue
        non_duplicated_source_functions[function_name] = source_functions[function_name]

    with open(os.path.join(output_dir, 'source_code_function.json'), 'w') as f:
        json.dump(non_duplicated_source_functions, f, indent=4)
        print("[+] Save non-dupicates results to", os.path.join(output_dir, 'source_code_function.json'))


def main(args):
    source_dir = args.source_dir
    output_dir = args.output_dir
    test_file = args.test_file

    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    process(source_dir, output_dir)
    remove_duplicates(test_file, output_dir)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract functions from source code and remove duplicates')
    parser.add_argument('-s', '--source_dir', type=str, required=True,
        # default='',
        help='Directory containing the source projects.')
    parser.add_argument('-t', '--test_file', type=str,  required=True,
        # default='',
        help='Path to the test set file for removing duplicates in the collected source function code. For example: /dataset/test_set.json.')
    parser.add_argument('-o', '--output_dir', type=str,  required=True,
        # default='',
        help='Directory to save the output JSON file.')

    args = parser.parse_args()

    main(args)
    