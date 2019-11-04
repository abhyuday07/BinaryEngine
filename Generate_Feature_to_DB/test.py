import binascii
import json
import math
import os
import sys
import re
from random import choice
sys.path.append('/home/wufeng/B2S/B2SFinder/DB')
import mongoDB
import subprocess

import Levenshtein
from collections import defaultdict

type_dict_64 = {'byte': 2,
                'char': 2,
                'int': 8,
                'short': 4,
                'long': 16,
                'unsigned int': 8,
                'unsigned short': 4,
                'unsigned long': 16,
                'long long': 16,
                'bool': 2,
                'unsigned char': 2,
                'float': 8,
                'double': 16,
                '__int8': 2,
                '__int16': 4,
                '__int32': 8,
                '__int64': 16,
                'long double': 16,
                'wchar_t': 4}

type_dict_32 = {'byte': 2,
                'char': 2,
                'int': 8,
                'short': 4,
                'long': 8,
                'unsigned int': 8,
                'unsigned short': 4,
                'unsigned long': 8,
                'long long': 16,
                'bool': 2,
                'unsigned char': 2,
                'float': 8,
                'double': 16,
                '__int8': 2,
                '__int16': 4,
                '__int32': 8,
                '__int64': 16,
                'long double': 16,
                'wchar_t': 4}


def get_pe_str_value(value, length):
    try:
        if value < 0:
            if length == 2:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xff)[2:]), 2)
            elif length == 4:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffff)[2:]), 4)
            elif length == 8:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffffffff)[2:]), 8)
            else:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffffffffffffffff)[2:]), 16)
        else:
            hex_num = hex(value)[2:]
            hex_search_str = get_little_endian(cut_L_tail(hex_num), length)
        return hex_search_str
    except ValueError:
        hex_search_str = get_little_endian(cut_L_tail(hex(value)[2:]), length)
        return hex_search_str


def get_little_endian(num, length):
    if length % 2 == 0:
        length = length
    else:
        length = length + 1
    num = '0' * (length - len(num)) + num
    hex_search_str = []
    count = len(num) - 2
    for i in range(0, int(len(num) / 2)):
        hex_search_str.append(num[count])
        hex_search_str.append(num[count + 1])
        count = count - 2
    hex_search_str = ''.join(hex_search_str)
    return hex_search_str


def cut_L_tail(hex_str):
    if hex_str[-1] == "L":
        return hex_str[:-1]
    return hex_str


def get_pe32_str(num_type, value):
    length = type_dict_32[num_type]
    try:
        if value < 0:
            if length == 2:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xff)[2:]), 2)
            elif length == 4:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffff)[2:]), 4)
            elif length == 8:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffffffff)[2:]), 8)
            else:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffffffffffffffff)[2:]), 16)
        else:
            hex_num = cut_L_tail(hex(value)[2:])
            hex_search_str = get_little_endian(hex_num, length)
        return hex_search_str
    except ValueError:
        return get_little_endian(cut_L_tail(hex(value)[2:]), length)


def get_pe64_str(num_type, value):
    length = type_dict_64[num_type]
    try:
        if value < 0:
            if length == 2:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xff)[2:]), 2)
            elif length == 4:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffff)[2:]), 4)
            elif length == 8:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffffffff)[2:]), 8)
            else:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffffffffffffffff)[2:]), 16)
        else:
            hex_num = hex(value)[2:]
            hex_search_str = get_little_endian(cut_L_tail(hex_num), length)
        return hex_search_str
    except ValueError:
        return get_little_endian(cut_L_tail(hex(value)[2:]), length)


def get_hex_search_list(const_num_arrays, lib_name):
    flag_x86 = True

    # num_array contains unrepeated array items
    num_array = dict()
    for arr in const_num_arrays:
        if len(arr["array"]) < 3:
            continue
        arr_tur = tuple(arr["array"])

        all_0_flag = True
        for item in arr_tur:
            if item != 0:
                all_0_flag = False
                break
        if all_0_flag:
            continue

        # ignore the case that two arrays has same value but different element type
        if arr_tur not in num_array:
            num_array[arr_tur] = {'count': 1, 'type': arr["element_type"],
                                  'array_name': [arr["var_name"] + '_' + lib_name], 'hex_list': [], 'score': 1}
        else:
            num_array[arr_tur]['count'] += 1
            num_array[arr_tur]['array_name'].append(arr["var_name"] + '_' + lib_name)
            continue
        num_type = num_array[arr_tur]['type']

        if num_type and num_type in type_dict_32:
            hex_search_str = ''
            for array_item in arr_tur:
                if flag_x86:
                    hex_search_str += get_pe32_str(num_type, array_item)
                else:
                    hex_search_str += get_pe64_str(num_type, array_item)
            num_array[arr_tur]['hex_list'].append(hex_search_str)
        else:
            max_item = max(arr_tur)
            waiting_potential_len = [2, 4, 8, 16]
            potential_len = []
            for plen in waiting_potential_len:
                if 16 ** plen <= max_item:
                    continue
                potential_len.append(plen)

            for length in potential_len:
                hex_search_str = ''
                for array_item in arr_tur:
                    cur_num = array_item
                    hex_search_str += get_pe_str_value(cur_num, length)
                num_array[arr_tur]['hex_list'].append(hex_search_str)

    hex_search_list = []
    hex_set = []
    for arr_tur in num_array:
        hex_set += num_array[arr_tur]['hex_list']
    hex_set = list(set(hex_set))
    for hex_item1 in hex_set:
        flag = True
        for hex_item2 in hex_set:
            if len(hex_item1) < len(hex_item2) and hex_item1 in hex_item2:
                flag = False
                break
        if flag:
            hex_search_list.append(hex_item1)

    new_num_array = {}
    for arr_tur in num_array:
        pre_hex_list = num_array[arr_tur]['hex_list']
        new_hex_list = []
        for item in pre_hex_list:
            if item in hex_search_list:
                new_hex_list.append(item)
        if len(new_hex_list):
            new_num_array[arr_tur] = num_array[arr_tur]
            new_num_array[arr_tur]['hex_list'] = new_hex_list
    return hex_search_list, new_num_array


def get_score(score=1, count=1, length=1, use_score=True):
    if not use_score:
        return count
    return (count * (math.log(length, 2) + 1)) / float(score)


def compare_arr2dll(hex_file, unrepeat_num_arr, use_score=True):
    success_match = 0
    success_match_num_len = 0
    total_count = 0
    total_num_len = 0
    for array_item in unrepeat_num_arr:
        for hex_item in unrepeat_num_arr[array_item]['hex_list']:
            # print(bytes(hex_item, 'utf-8'))
            pos = hex_file.find(bytes(hex_item, 'utf-8'))
            if pos != -1:
                # print("\t\tmatch:", hex_item, array_item, unrepeat_num_arr[array_item]['array_name'], hex(pos),
                #       unrepeat_num_arr[array_item]['count'], unrepeat_num_arr[array_item]['score'],
                #       get_score(score=unrepeat_num_arr[array_item]['score'],
                #                 count=unrepeat_num_arr[array_item]['count'], length=len(array_item),
                #                 use_score=use_score))
                success_match += get_score(score=unrepeat_num_arr[array_item]['score'],
                                           count=unrepeat_num_arr[array_item]['count'], length=len(array_item),
                                           use_score=use_score)
                success_match_num_len += len(array_item) * get_score(score=unrepeat_num_arr[array_item]['score'],
                                                                     count=unrepeat_num_arr[array_item]['count'],
                                                                     use_score=use_score)
                break
        total_count += get_score(score=unrepeat_num_arr[array_item]['score'],
                                 count=unrepeat_num_arr[array_item]['count'], length=len(array_item),
                                 use_score=use_score)
        total_num_len += len(array_item) * get_score(score=unrepeat_num_arr[array_item]['score'],
                                                     count=unrepeat_num_arr[array_item]['count'], use_score=use_score)
    # print("\t\t >> success_match:", success_match, "total_count:", total_count, "success_match_num_len:",
    #       success_match_num_len, "total_num_len:", total_num_len)
    return success_match, total_count


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
        file = os.listdir(tmp_path)[0]
        binary_path = os.path.join(tmp_path, file)
        os.system("dpkg -x %s %s" % (binary_path, tmp_path))
        os.system("rm %s" % binary_path)
    else:
        return 0
    return tmp_path


def is_debian_file(filename):
    cmd = "file %s" % filename
    try:
        cmd_out = subprocess.check_output(cmd, shell=True)
    except Exception as e:
        return False
    if "ELF" in cmd_out.decode():
        return True
    return False


def code_preprocess(code):
    bad_char = '\n\t\r\x0a\x0d\x20'
    return re.sub(r'[^\x01-\x7F]', ' ', code.strip().translate(str.maketrans("", "", bad_char)))


def match_const_num_array(bin_file, num_arrays, lib_name, use_score=True, record_details=False):
    [hex_search_list, unrepeat_num_arr] = get_hex_search_list(num_arrays, lib_name)
    if not len(unrepeat_num_arr):
        return 0, 0, []
    with open(bin_file, "rb") as f:
        content = f.read()
        num_hex_file = binascii.b2a_hex(content)
    success_match, total_count = compare_arr2dll(num_hex_file, unrepeat_num_arr, use_score=use_score)
    return success_match, total_count


def match_enum_array(bin_file, const_enum_arrays, lib_name, use_score=True):
    [hex_search_list, unrepeat_num_arr] = get_hex_search_list(const_enum_arrays, lib_name)
    if not len(unrepeat_num_arr):
        return 0, 0, 0, []
    with open(bin_file, "rb") as f:
        content = f.read()
        enum_hex_file = binascii.b2a_hex(content)
    success_match, total_count = compare_arr2dll(enum_hex_file, unrepeat_num_arr, use_score=use_score)
    return success_match, total_count


def strings_compare(source_string_arrays, binary_string_arrays):
    count = 0
    total_count = 0
    for source_item in source_string_arrays:
        for string_arr in source_item['array']:
            total_count += 1
            tmp_result = defaultdict(list)
            for binary_item in binary_string_arrays:
                try:
                    binary_item = binary_item.decode('utf-8')
                    if binary_item in ['\n', ' \n', '\t', ' ']:
                        continue
                    binary_item=code_preprocess(binary_item)
                    string_arr=code_preprocess(string_arr)
                    score = Levenshtein.jaro_winkler(string_arr, binary_item)
                    if score > 0.7:
                        tmp_result["score"].append(score)
                        tmp_result["binary_item"].append(binary_item)
                except Exception as e:
                    continue
            if len(tmp_result)>0:
                score_index = tmp_result['score'].index(max(tmp_result['score']))
                print(max(tmp_result['score']))
                print("source_string_item can be found in binary_file.\n\t source_item:%s \n\t binary_item: %s" % (string_arr, tmp_result['binary_item'][score_index]))
                count += 1
    # print(
    #     "[++string array++]totoal string arrays: %d, matched string arrays: %d, matched ratio: %f, matched confidence: 0.6" % (
    #         len(source_string_arrays), count, float(count) / len(source_string_arrays)))
    return float(count) / total_count


def match_strings_array(elf_file, source_string_arrays):
    cmd = "readelf -p .rodata %s" % elf_file
    res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           close_fds=True)
    binary_string_arrays = res.stdout.readlines()
    result = strings_compare(source_string_arrays, binary_string_arrays)
    return result


def quary_source_binary_array(source_dir, elf_files, library_name):
    files = os.listdir(source_dir)
    for file in files:
        if library_name in file:
            print(file)
            with open(os.path.join(source_dir, file), 'r') as file_read:
                data_json = json.load(file_read)
                invalid = False
                for cpp_file in data_json:
                    flag_enum_arrays = False
                    flag_num_arrays = False
                    flag_string_arrays = False
                    enum_score = 0
                    num_score = 0
                    string_score = 0
                    if len(data_json[cpp_file]['const_enum_arrays']) != 0:
                        print("[++enum scan++]....")
                        for elf_file in elf_files:
                            matched_count, total_count = match_enum_array(elf_file,
                                                                          data_json[cpp_file]['const_enum_arrays'] +
                                                                          data_json[cpp_file]['ori_const_enum_arrays'],
                                                                          "test", use_score=True)
                            if total_count > 5:
                                if (total_count >= 50 and float(matched_count) / total_count >= 0.5) or (
                                        float(matched_count) / total_count >= 0.7):
                                    flag_enum_arrays = True
                                    enum_score = float(matched_count) / total_count
                    if len(data_json[cpp_file]['const_num_arrays']) != 0:
                        print("[++num scan++]....")
                        for elf_file in elf_files:
                            matched_count, total_count = match_const_num_array(elf_file,
                                                                               data_json[cpp_file]['const_num_arrays'] +
                                                                               data_json[cpp_file][
                                                                                   'ori_const_num_arrays'],
                                                                               "test", use_score=True)

                            if total_count > 5:
                                if (total_count >= 50 and float(matched_count) / total_count >= 0.5) or (
                                        float(matched_count) / total_count >= 0.7):
                                    flag_num_arrays = True
                                    num_score = float(matched_count) / total_count
                    if len(data_json[cpp_file]['string_arrays']) != 0:
                        print("[++string scan++]....")
                        for elf_file in elf_files:
                            string_array_score = match_strings_array(elf_file, data_json[cpp_file]['string_arrays'])
                            if string_array_score > 0.6:
                                flag_string_arrays = True
                                string_score = string_array_score
                    if flag_enum_arrays:
                        print(
                            "[++enum_array_result++]source file : %s \t binary_library : %s \n elf_file: %s \t score: %f" % (
                                file, library_name, elf_file, enum_score))
                    if flag_num_arrays:
                        print(
                            "[++num_array_result++]source file : %s \t binary_library : %s \n elf_file: %s \t score: %f" % (
                                file, library_name, elf_file, num_score))
                    if flag_string_arrays:
                        print(
                            "[++string_array_result++]source file : %s \t binary_library : %s \n elf_file: %s \t score: %f" % (
                                file, library_name, elf_file, string_score))


if __name__ == "__main__":
    source_dir = '/home/wufeng/B2S/B2SFinder/SourceFeatureExtract/output'
    db_name = mongoDB.mongodb_synic(host='localhost', username='root', password='example', port=27018,
                                    authSource='admin',
                                    db_name='binary_engine_test_db', collection_name='array_feature_test_item')
    collection = db_name.do_query()
    cursor = collection.find({})
    for document in cursor:
        document.pop('_id')
        for key in document:
            library_name = key
            source_urls = document[key]['source_code']
            binary_urls = document[key]['binary_code']
            version = choice(binary_urls)
            file_path = download_url(version)
            if file_path == 0:
                continue
            elf_files = []
            for root, dirs, binary_files in os.walk(file_path):
                for binary_file in binary_files:
                    if is_debian_file(os.path.join(root, binary_file)):
                        elf_files.append(os.path.join(root, binary_file))
            quary_source_binary_array(source_dir, elf_files, library_name)
