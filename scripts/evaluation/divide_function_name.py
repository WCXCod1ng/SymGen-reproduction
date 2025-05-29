import os
import json
import argparse
import sentencepiece as spm
from nltk.stem.wordnet import WordNetLemmatizer
from nltk.corpus import wordnet
import nltk


nltk.download('averaged_perceptron_tagger')
nltk.download('wordnet')
nltk.download('averaged_perceptron_tagger_eng')


sp = spm.SentencePieceProcessor()
sp.load('evaluation/segmentation_model/segmentation.model')
lem = WordNetLemmatizer()


def get_pos(treebank_tag):
    """
    get the pos of a treebank tag
    """
    if treebank_tag.startswith('J'):
        return wordnet.ADJ
    elif treebank_tag.startswith('V'):
        return wordnet.VERB
    elif treebank_tag.startswith('N'):
        return wordnet.NOUN
    elif treebank_tag.startswith('R'):
        return wordnet.ADV
    else:
        return None # for easy if-statement


def func_name_segmentation(word):
    """
    Segment concatenated words into individual words
    """
    res = sp.encode_as_pieces(word)
    res[0] = res[0][1:]
    return res


def func_name_preprocessing(func_name):
    """
    Preprocess function name by:
        - tokenize whole name into words
        - remove digits
        - segment concatenated words
        - lemmatize words
    """
    func_name = func_name.lower()
    # split whole name into words and remove digits
    func_name = func_name.replace('_', ' ')
    tmp = ''
    for c in func_name:
        if not c.isalpha():  # filter out numbers and other special characters, e.g. '_' and digits
            tmp = tmp + ' '
        elif c.isupper():
            tmp = tmp + ' ' + c
        else:
            tmp = tmp + c
    tmp = tmp.strip()
    tmp = tmp.split(' ')

    res = []
    i = 0
    while i < len(tmp):
        cap = ''
        t = tmp[i]

        # handle series of capital letters: e.g., SHA, MD
        while i < len(tmp) and len(tmp[i]) == 1:
            cap = cap + tmp[i]
            i += 1
        if len(cap) == 0:
            res.append(t)
            i += 1
        else:
            res.append(cap)

    # lemmatize words
    words = []
    for word in res:
        if not isinstance(word, str) or word == '':
            continue
        words.append(word)
    tokens = nltk.pos_tag(words)
    res = []
    for word, tag in tokens:
        wntag = get_pos(tag)
        if wntag is None:  # not supply tag in case of None
            word = lem.lemmatize(word)
        else:
            word = lem.lemmatize(word, pos=wntag)
        res.append(word)

    # segment concatenated words
    final_words = []
    for word in res:
        if not isinstance(word, str) or word == '':
            continue
        splited = func_name_segmentation(word)
        for w in splited:
            if not isinstance(w, str) or w == '':
                continue
            final_words.append(w)

    if len(final_words) == 0:
        return None
    
    resulting_name = ' '.join(final_words)
    return resulting_name.lower()


def main(args):
    input_file = args.input_file
    output_dir = args.output_dir

    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(input_file, 'r') as f:
        results = json.load(f)

        for result in results:
            ground_truth = func_name_preprocessing(result['ground_truth'].split(' ')[-1].strip())
            if ground_truth is None:
                continue

            prediction = result['predicted_name'].split('</s>')[0]

            if prediction.find('\"') != -1:
                prediction = prediction.split('\"')[1]
            if prediction.find('`') != -1:
                prediction = prediction.split('`')[1]
            prediction = prediction.split('.')[0].strip()
            prediction = prediction.split(' ')[-1].strip()

            prediction = func_name_preprocessing(prediction)
            if prediction is None:
                prediction = ' '

            file = open(os.path.join(output_dir, 'processed_predicted_function_name.txt'), 'a')
            file.write(ground_truth + ', ' + prediction + ',\n')
            file.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Preprocess the predicted function name for evaluation.')
    parser.add_argument('-i', '--input_file', type=str, required=True,
        # default='',
        help='Path to the input file containing predicted function names and ground truth.')
    parser.add_argument('-o', '--output_dir', type=str, required=True,
        # default='',
        help='Directory to save the evaluation results.')

    args = parser.parse_args()

    main(args)
    