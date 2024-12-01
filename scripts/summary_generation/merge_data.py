import os
import json
import random
import argparse


def main(args):
    training_data = args.training_data
    summary_data = args.summary_data
    output_dir = args.output_dir

    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)


    with open(training_data, 'r') as f:
        trainData = json.load(f)

    with open(summary_data, 'r') as f:
        summaryData = json.load(f)


    for item in trainData:
        summaryData.append(item)

    # random.shuffle(trainData)

    with open(os.path.join(output_dir, "training_set_with_summary.json"), 'w') as f:
        json.dump(summaryData, f, indent=4)
        print("[+] Save merged training set to", os.path.join(output_dir, "training_set_with_summary.json"))


if __name__ == '__main__':  
    parser = argparse.ArgumentParser(description='Merge decompiled function training set with function summary data into a new training set')
    parser.add_argument('-t', '--training_data', type=str, required=True,
        # default='',
        help='Path to the JSON file containing the decompiled training set.')
    parser.add_argument('-s', '--summary_data', type=str, required=True,
        # default='',
        help='Path to the JSON file containing function summaries.')
    parser.add_argument('-o', '--output_dir', type=str, required=True,
        # default='',
        help='Directory to save the merged training set.')

    args = parser.parse_args()

    main(args)