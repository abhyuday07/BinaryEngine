import os
from collections import Counter
# from flask import current_app as app
import time
import subprocess
import binascii
import utils
import sys
import random
sys.path.append('/home/wufeng/B2S/B2SFinder/Generate_Feature_to_DB')
sys.path.append('/home/wufeng/B2S/B2SFinder/Binary_Engine')
sys.path.append('/home/wufeng/B2S/B2SFinder/DB')
import mongodb_bloomfilter
import config
import mongoDB
# This will store information about the decision for analysis


def get_elf_segment_names(filepath):
    """
    :param filepath: path of binary file
    :return: ['.data', '.text', ... ]
    """
    command = 'readelf -S "%s"' % filepath
    command_output = os.popen(command).read().split('\n')
    segment_name_list = []
    for each_line in command_output:
        if len(each_line) > 7:
            if each_line[7] == '.':
                segment_name_list.append(each_line[7:].split()[0])
    return segment_name_list


def get_string_from_elf(filename):
    """
    :param filename: path of binary file
    :return: "string1 string2 ..."
    """
    # _ = os.system('strip "%s"' % filename)
    all_strings = os.popen("strings \"%s\"" % filename).read().split('\n')
    segment_names = set(get_elf_segment_names(filename))
    valid_strings = []
    for x in all_strings:
        if x not in segment_names:
            valid_strings.append(x)
    return " ".join(valid_strings)


def get_string_array_from_elf(filename):
    string_array_list = []
    cmd = 'readelf -p .rodata %s' % filename
    res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           close_fds=True)
    binary_string_arrays = res.stdout.readlines()
    for item in binary_string_arrays:
        try:
            item = item.decode('utf-8')
            if item in ['\n', ' \n', '\t', ' ']:
                continue
            item = utils.code_preprocess(item)
            if len(item) > 5:
                string_array_list.append(item)
        except Exception as e:
            continue
    return string_array_list


def get_features_of_deb(libpath):
    """
    :param libpath: path of binary file
    :return: "string1 string2 ..."
    """
    all_elf_files = utils.get_elf_files_list(libpath)
    strings_list = []
    strings_array_list = []
    for x in all_elf_files:
        strings_list.append(get_string_from_elf(x))
        strings_array_list.extend(get_string_array_from_elf(x))
    return " ".join(strings_list), strings_array_list, all_elf_files


def generate_grams(target_strings, num):
    """
    :param target_strings: ['str1', 'str2', 'str3', ..., 'str_n']
    :param num: int
    :return: ['str1 str2 ... str_m', 'str2 str3 ... str_m+1', ...] m=num
    """
    list_len = len(target_strings)
    target_strings_new = []
    for i in range(list_len - num + 1):
        target_strings_new.append(" ".join(target_strings[i:i + num]))
    return target_strings_new


def query_string_feature_mongodb(target_strings_dict, counter, use_weights=True, user_tfidf=True):
    """
    :param target_strings: {str1, str2, str3, ...}
    :param type: fn, 1g, 2g, 3g, string
    :param use_weights: boolean
    :param user_tfidf: boolean
    :param counter: {lib1:count, lib2:count, lib3:count, ...}
    :return:
    """
    start_time = time.time()
    print("[++string feature++]query_mongodb ...")
    weights = 1
    mongoDB_sync = mongodb_bloomfilter.MongoDB_Sync()
    feature_result = mongoDB_sync.multi_process_query([config.db_fn_collection, config.db_1g_collection, config.db_2g_collection, config.db_3g_collection],
                                                      config.db_core,
                                                      feature_data=target_strings_dict,
                                                      batch_size=config.db_batch_size)
    count_result = {}
    for key in feature_result:
        count_result[key] = len(feature_result[key])
    # type of result:dict
    # {lib1_fn: count1, lib1_1g: count2, lib1_2g: count3, ..., }
    print("finished query_mongodb, time is %f" % (time.time() - start_time))
    for key in count_result:
        lib_id = key[:-3]
        if lib_id not in counter.keys():
            counter[lib_id] = count_result[lib_id + '_fn'] * config.feature_fn_weights + count_result[lib_id + '_1g'] * config.feature_1g_weights + count_result[
                lib_id + '_2g'] * config.feature_2g_weights + count_result[lib_id + '_3g'] * config.feature_3g_weights
    return counter, count_result


def predict_libs_with_strings(target_strings, analyse, most_commons=3, use_weights=True, use_tfidf=True):
    target_strings = utils.refine_strings(target_strings)
    counter = Counter()
    new_target_strings = {}
    target_strings_1g = target_strings
    target_strings_2g = generate_grams(target_strings, 2)
    target_strings_3g = generate_grams(target_strings, 3)

    new_target_strings['1g'] = list(set(target_strings_1g))
    new_target_strings['2g'] = list(set(target_strings_2g))
    new_target_strings['3g'] = list(set(target_strings_3g))
    new_target_strings['fn'] = list(set(target_strings_1g))

    counter, count_result = query_string_feature_mongodb(new_target_strings, counter)
    result = {}
    most_common_library_N = [x[0] for x in counter.most_common(most_commons)]
    for lib_id in most_common_library_N:
        result[lib_id] = {"total_score": counter[lib_id], "fn_count": count_result[lib_id + '_fn'],
                          "1g_count": count_result[lib_id + '_1g'],
                          "2g_count": count_result[lib_id + '_2g'], "3g_count": count_result[lib_id + '_3g'], }
    # # If analyse is ON, information for debug is saved.
    # if analyse:
    #     json.dump(result_info, open('result_info.json', 'w'), indent=4)
    #     print("Result details are saved in result_info.json for further analysis.")
    return result


def predict_libs_with_string_arrays(target_strings_array):
    start_time = time.time()
    print("[++string array feature++]query_mongodb ...")
    mongoDB_sync = mongodb_bloomfilter.MongoDB_Sync()
    feature_result = mongoDB_sync.multi_process_query([config.db_string_array_collection],
                                                      config.db_core,
                                                      feature_data={config.db_string_array_collection: target_strings_array},
                                                      batch_size=config.db_batch_size)
    print("finished query_mongodb, time is %f" % (time.time() - start_time))
    # for key in feature_result:
    #     if len(feature_result[key]) != 0:
    #         print(feature_result)
    #         break
    return feature_result


def predict_libs_with_const_num_arrays(elf_hex_files):
    start_time = time.time()
    print("[++const num array feature++]query_mongodb ...")
    mongoDB_sync = mongodb_bloomfilter.MongoDB_Sync()
    feature_result = mongoDB_sync.multi_process_query([config.db_const_num_array_collection],
                                                      config.db_core,
                                                      feature_data={config.db_const_num_array_collection: elf_hex_files},
                                                      batch_size=config.db_batch_size)
    print("finished query_mongodb, time is %f" % (time.time() - start_time))
    # for key in feature_result:
    #     if len(feature_result[key]) != 0:
    #         print(feature_result)
    #         break
    return feature_result


def predict_libs_with_const_enum_arrays(elf_hex_files):
    start_time = time.time()
    print("[++const enum array feature++]query_mongodb ...")
    mongoDB_sync = mongodb_bloomfilter.MongoDB_Sync()
    feature_result = mongoDB_sync.multi_process_query([config.db_const_enum_array_collection],
                                                      config.db_core,
                                                      feature_data={config.db_const_enum_array_collection: elf_hex_files},
                                                      batch_size=config.db_batch_size)
    print("finished query_mongodb, time is %f" % (time.time() - start_time))
    # for key in feature_result:
    #     if len(feature_result[key]) != 0:
    #         print(feature_result)
    #         break
    return feature_result


def logger_save(string_result, string_array_result, const_num_result, const_enum_result, repo_name,
                string_array_number, logger_write):
    logger_write.write("Repo:\t%s\n" % repo_name)
    logger_write.write("process for analysis")
    logger_write.write("FEATURE *** [fn, 1g, 2g, 3g]\n")
    string_max_score = 0.0
    string_max_item = ""
    for item in string_result:
        if len(string_result[item]) > 0:
            if float(string_result[item]['total_score']) > string_max_score:
                string_max_item = item.split("string_feature")[0]
                string_max_score = float(string_result[item]['total_score'])
            logger_write.write("library_name/version: %s\t score: %s\t fn:%s\t 1g: %s\t 2g: %s\t 3g: %s\n" % (
                item.split("string_feature")[0], string_result[item]['total_score'], string_result[item]['fn_count'],
                string_result[item]['1g_count'], string_result[item]['2g_count'], string_result[item]['3g_count']))

    logger_write.write("FEATURE *** string arrays\n")
    string_array_max_ratio = 0.0
    string_array_max_item = ""
    for item in string_array_result:
        if len(string_array_result[item]) > 0 and len(string_array_result[item]['score']) > 10:
            if len(string_array_result[item]['score']) / string_array_number > string_array_max_ratio:
                string_array_max_ratio = len(string_array_result[item]['score']) / string_array_number
                string_array_max_item = item.split("string_arrays_feature")[0]
            logger_write.write("library_name/version: %s\t average score: %s\t ratio: %s/%s\n" % (
                item.split("string_arrays_feature")[0], sum(string_array_result[item]['score']) / len(string_array_result[item]['score']),
                len(string_array_result[item]['score']), str(string_array_number)))

    logger_write.write("FEATURE *** const_num_array\t\n")
    const_num_array_max_ratio = 0.0
    const_num_array_max_item = ""
    for item in const_num_result:
        if len(const_num_result[item]) > 0 and (len(const_num_result[item]['matched_count']) == 1 and int(const_num_result[item]['matched_count'][0]) != 0):
            if float(const_num_result[item]['matched_count'][0])/float(const_num_result[item]['total_count'][0]) > const_num_array_max_ratio:
                const_num_array_max_ratio = float(const_num_result[item]['matched_count'][0])/float(const_num_result[item]['total_count'][0])
                const_num_array_max_item = item.split("const_num_arrays_feature")[0]
            logger_write.write("library_name/version: %s\t matched_count: %s\t total_count: %s\n" % (
                item, const_num_result[item]['matched_count'][0], const_num_result[item]['total_count'][0]))

    logger_write.write("FEATURE *** const_enum_array\t\n")
    const_enum_array_max_ratio = 0.0
    const_enum_array_max_item = ""
    for item in const_enum_result:
        if len(const_enum_result[item]) > 0 and (len(const_enum_result[item]['matched_count']) == 1 and int(const_enum_result[item]['matched_count'][0]) != 0):
            if float(const_enum_result[item]['matched_count'][0])/float(const_enum_result[item]['total_count'][0]) > const_enum_array_max_ratio:
                const_enum_array_max_ratio = float(const_enum_result[item]['matched_count'][0])/float(const_enum_result[item]['total_count'][0])
                const_enum_array_max_item = item.split("const_enum_arrays_feature")[0]
            logger_write.write("library_name/version: %s\t matched_count: %s\t total_count: %s\n" % (
                item.split("const_enum_arrays_feature")[0], const_enum_result[item]['matched_count'][0], const_enum_result[item]['total_count'][0]))

    logger_write.write("RESULT\n \t %s\n"%repo_name)
    if string_max_score == 0.0:
        logger_write.write("string: no found in DB..\n")
    else:
        logger_write.write("string: %s, score: %f\n" %(string_max_item, string_max_score))
    if string_array_max_ratio < config.string_array_max_ratio:
        logger_write.write("string_arrays: no found in DB ..\n")
    else:
        logger_write.write("string arrays: %s, ratio: %f\n"%(string_array_max_item, string_array_max_ratio))
    if const_num_array_max_ratio < config.const_num_array_max_ratio:
        logger_write.write("const_num_arrays: no found in DB .. \n")
    else:
        logger_write.write("const_num_arrays: %s, ratio: %f\n"%(const_num_array_max_item, const_num_array_max_ratio))
    if const_enum_array_max_ratio < config.const_enum_array_max_ratio:
        logger_write.write("const_enum_arrays: no found in DB .. \n\n")
    else:
        logger_write.write("const_enum_arrays: %s, ratio: %f\n\n" % (const_enum_array_max_item, const_enum_array_max_ratio))


def predict_libs(target_file_path, repo_name, logger_write):
    """
    :param target_file_path: deb file or elf file path
    :param most_commons: n-grams n
    :param analyse: save debug information or not
    :return: [predicted_library, [lib_1, lib_2, lib_3], Counter({lib_1: lib_1_score, lib_2: lib_2_score, ... })]
    """
    elf_files = []
    elf_hex_files = []
    if target_file_path.endswith('.deb'):
        target_strings, target_strings_array, elf_files = get_features_of_deb(target_file_path)
    else:
        target_strings = get_string_from_elf(target_file_path)
        target_strings_array = get_string_array_from_elf(target_file_path)
        elf_files.append(target_file_path)
    for file in elf_files:
        with open(file, 'rb') as elf_rb_read:
            content = elf_rb_read.read().strip()
            elf_hex_files.append(binascii.b2a_hex(content))

    string_result = predict_libs_with_strings(target_strings, analyse=True)
    string_array_result = predict_libs_with_string_arrays(target_strings_array=target_strings_array)
    const_num_result = predict_libs_with_const_num_arrays(elf_hex_files)
    const_enum_result = predict_libs_with_const_enum_arrays(elf_hex_files)
    print("[++result++]save result ....")
    logger_save(string_result, string_array_result, const_num_result, const_enum_result, repo_name,
                len(target_strings_array), logger_write)
    print("[++result++]finished")


def download_url(url):
    tmp_path = os.path.join(os.getcwd(), 'binary_tmp/')
    if not os.path.exists(tmp_path):
        os.system("mkdir %s" % tmp_path)
    else:
        os.system("rm -r %s" % tmp_path)
        os.system("mkdir %s" % tmp_path)
    print(url)
    # print(tmp_path)
    os.system("wget -q -P %s %s" % (tmp_path, url))
    if len(os.listdir(tmp_path)) != 0:
        return tmp_path + os.listdir(tmp_path)[0], os.listdir(tmp_path)[0]
    else:
        return 0, 0


if __name__ == "__main__":
    mongoDB_sync = mongoDB.mongodb_synic(host=config.db_host,
                                         port=config.db_port,
                                         db_name=config.db_test_data,
                                         collection_name=config.db_test_collection)
    collection = mongoDB_sync.do_query()
    logger_path = os.path.join(os.getcwd(), 'logger.txt')
    with open(logger_path, 'w') as logger_write:
        cursor = collection.find({})
        for document in cursor:
            document.pop('_id')
            for key in document:
                library_name = key
                source_urls = document[key]['source_code']
                binary_urls = document[key]['binary_code']
                if len(binary_urls) >= 2:
                    versions = random.sample(binary_urls.keys(), 2)
                    for version in versions:
                        file_path, repo_name = download_url(binary_urls.get(version))
                        if file_path == 0:
                            continue
                        predict_libs(file_path, repo_name, logger_write)
