import os
import sys
import time

import fire
import torch
import transformers
from openai import OpenAI
from peft import PeftModel
from transformers import GenerationConfig, LlamaForCausalLM, CodeLlamaTokenizer

from utils.callbacks import Iteratorize, Stream
from utils.prompter import Prompter

import json

def main(
        input_path: str = "",
        output_dir: str = "",
):
    assert (
        input_path
    ), "Please specify a --input_path"

    assert (
        output_dir
    ), "Please specify a --output_dir"

    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    client = OpenAI(api_key="sk-bba10b106ee64b0ba4f59e880500a22e", base_url="https://api.deepseek.com/v1")
    def evaluate(
            instruction=None,
            input=None,
            temperature=0.1,
            top_p=0.75,
            top_k=40,
            num_beams=1,
            max_new_tokens=256,
            stream_output=False,
            **kwargs,
    ):
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": instruction},
                # {"role": "user", "content": "\nvoid [MASK](undefined8 param_1,void *param_2,long param_3)\n\n{\n  int iVar1;\n  undefined8 *puVar2;\n  void *pvVar3;\n  undefined8 uVar4;\n  \n  puVar2 = (undefined8 *)FUN_0001f967(0x10);\n  pvVar3 = memchr(param_2,0x2f,param_3 - (long)param_2);\n  if (pvVar3 == (void *)0x0) {\n    uVar4 = wget_strmemdup(param_2,param_3 - (long)param_2);\n    *puVar2 = uVar4;\n    puVar2[1] = 0;\n  }\n  else {\n    uVar4 = wget_strmemdup(param_2,(long)pvVar3 - (long)param_2);\n    *puVar2 = uVar4;\n    uVar4 = wget_strmemdup((long)pvVar3 + 1,(param_3 - (long)pvVar3) + -1);\n    puVar2[1] = uVar4;\n  }\n  iVar1 = wget_vector_find(param_1,puVar2);\n  if (iVar1 < 0) {\n    wget_vector_insert_sorted(param_1,puVar2);\n  }\n  else {\n    FUN_000208e1(puVar2);\n  }\n  return;\n}\n\n",},
                # {"role": "assistant", "content": "The predicted function name is add_tag.</s>"},
                {"role": "user", "content": input}
            ],
            model="deepseek-chat",
            temperature=temperature,
            top_p=top_p,
            max_completion_tokens=max_new_tokens,
            stream=stream_output
        )
        content = response.choices[0].message.content
        return content

    with open(os.path.join(output_dir, 'predicted_function_name.json'), 'w') as f:
        json.dump([], f, indent=4)

    with open(input_path) as f:
        testset = json.load(f)

    it = 0
    for t in testset:
        instruction = """Suppose you are an expert in software reverse engineering. Here is a piece of decompiled code, you should infer code semantics and tell me the original function name from the contents of the function to replace [MASK]. And you need to tell me your answer (You should response in the form of "The predicted function name is <predicted_function_name>.</s>"):"""
        print('-' * 20, "Test Case", it, '-' * 20, )
        new_data = {}
        try:
            predicted_name = evaluate(instruction, t["input"])
            print(t["input"])
            print(predicted_name)

            new_data['ground_truth'] = t["output"]
            new_data['predicted_name'] = predicted_name
        except Exception as e:
            print(e)
            new_data['ground_truth'] = t["output"]
            new_data['predicated_name'] = "error"

        time.sleep(5)
        it = it + 1

        # with open(os.path.join(output_dir, 'predicted_function_name.json'), 'w') as f:
        #     json.dump(inference_result, f, indent=4)

        with open(os.path.join(output_dir, 'predicted_function_name.json'), 'r+') as f:
            data_for_update = json.load(f)
            data_for_update.append(new_data)
            f.seek(0)
            f.truncate()
            json.dump(data_for_update, f, indent=4)


if __name__ == "__main__":
    fire.Fire(main)