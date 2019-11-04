import json
import os
import math
import re
import subprocess
import traceback
from natsort import natsorted
# #from flask import current_app as app
# from core_engine.tools.db.utils import get_lib_vers
from dvast_common_words import most_common_words

# These global variables are used to modify strings to make it relevant to the model
invalid_pattern = re.compile(r"^[x0-9a-f\-]+$")
floating_num_pattern = re.compile(r'[0-9.]+')
PATHS_TO_IGNORE = ['/consolefonts/ ', '/man/', '/man1/', '/man2/', '/man3/', '/man4/', '/man5/', '/man6/', '/man7/',
                   '/man8/', '/systemd/', '/doc/', '/media/', '__macosx']
EXT_TO_IGNORE = ['bat', 'sh', 'txt', 'py', 'js', 'pyc', 'java', 'class', 'conf', 'md', 'rb', 'html', 'xml', 'json',
                 'control', 'service', 'list', 'md5', 'log', 'target', 'cgi', 'rules', 'h', 'c', 'cpp', 'pem', 'jsp',
                 'xhtml', 'css', 'png', 'jpg', 'jpeg', 'text', 'pdf', 'csv', 'doc', 'php', 'ini', 'yaml', 'preinst',
                 'postinst', 'prerm', 'postrm', 'ttf', 'ogg', 'kcm', 'psr', 'ico', 'pak', 'vim']

# The following types are generated/complianced with the OS tool "file"
INTERESTED_FILE_TYPE = ["PE32", "ELF", "Mach-O", "filesystem data", "compressed data", "executable", "archive",
                        "archive data", "Dalvik", "data"]


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


TIMEOUT_SECONDS = 7200


def exec_command(cmd, work_dir='.', timeout=TIMEOUT_SECONDS):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=work_dir)
    try:
        out, err = p.communicate(timeout=timeout)
        if err:
            return {'error': err}
    except Exception as e:
        return {'error': traceback.format_exc()}
    return {'output': out.strip()}


# def get_lib_vers(lib_name, vendor_name, platform):
#     if not vendor_name:
#         vendor_name = ''
#     lib_ids = []
#     ver_nums = []
#     # for tuple in ScantistLibrary.query.filter_by(name=lib_name, vendor=vendor_name).with_entities(ScantistLibrary.id):
#     for tuple in ScantistLibrary.query.filter(func.lower(ScantistLibrary.name) == lib_name.lower(),
#                                               func.lower(ScantistLibrary.vendor) == vendor_name.lower(),
#                                               func.lower(ScantistLibrary.platform) == platform.lower(),
#                                               ScantistLibrary.is_valid == True).with_entities(
#         ScantistLibrary.id):
#         lib_ids.append(tuple[0])
#     # app.logger.debug("\n\n\n[+++] get_lib_vers, lib_ids=%s\n\n\n", str(lib_ids))
#     # for tuple in ScantistLibraryVersion.query.filter(ScantistLibraryVersion.library_id.in_(lib_ids), ScantistLibraryVersion.is_valid).with_entities(
#     # for tuple in ScantistLibraryVersion.query.filter(ScantistLibraryVersion.library_id.in_(lib_ids)).with_entities(
#     for tuple in ScantistLibraryVersion.query.filter(ScantistLibraryVersion.library_id.in_(lib_ids),
#                                                      ScantistLibraryVersion.is_valid == True).with_entities(
#         ScantistLibraryVersion.version_number):
#         ver_nums.append(tuple[0])
#     return ver_nums


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


def compare_arr2dll(hex_file, unrepeat_num_arr, use_score=True):
    success_match = 0
    success_match_num_len = 0
    total_count = 0
    total_num_len = 0
    for array_item in unrepeat_num_arr:
        for hex_item in unrepeat_num_arr[array_item]['hex_list']:
            pos = hex_file.find(bytes(hex_item, 'utf-8'))
            if pos != -1:
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


def get_score(score=1, count=1, length=1, use_score=True):
    if not use_score:
        return count
    return (count * (math.log(length, 2) + 1)) / float(score)


def code_preprocess(code):
    bad_char = '\n\t\r\x0a\x0d\x20'
    return re.sub(r'[^\x01-\x7F]', ' ', code.strip().translate(str.maketrans("", "", bad_char)))


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
    return new_num_array


def get_elf_files_list(deb_filename):
    """
    It will create a tmp_filename folder in the current directory and extract deb file inside that
    then, it will return the list of the paths of all elf files present in the tmp folder
    :param deb_filename: path of deb file
    :return: list of the paths of elf files present in the given deb file
    """
    # Extract deb file
    elf_files = []
    tmp_dir = os.path.join(os.getcwd(), 'tmp_binary_deb')
    if os.path.exists(tmp_dir):
        os.system("rm -r %s"%tmp_dir)
        os.system("mkdir %s"%tmp_dir)
    else:
        os.system("mkdir %s"%tmp_dir)
    os.system("dpkg -x %s %s"%(deb_filename, tmp_dir))

    for root, folders, files in os.walk(tmp_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            cmd = "file \"%s\"" % filepath
            cmd_out = subprocess.check_output(cmd, shell=True)
            if "ELF" in cmd_out.decode():
                elf_files.append(filepath)
    return elf_files


def preprocess_string(s):
    """
    Each character of the given string except alpha-numeric character or _-. is replaced by a space
    In the new strings, if '.' is followed by space of is last character then it is removed too
    :param s: string
    :return: given string with the modification by replacing all the characters of string which are not alpha-numeric or _-. with spaces
    """
    nx = []
    l = len(s)
    for ic in range(l):
        c = s[ic]
        if c.isalnum() or (c in "_-."):
            # If last character of any word is '.' then we are removing this '.'
            if c == '.':
                if ic + 1 < l:
                    if s[ic + 1].isspace():
                        nx.append(" ")
                    else:
                        nx.append(c)
                else:
                    nx.append(" ")
            else:
                nx.append(c)
        else:
            nx.append(" ")
    return ("".join(nx)).strip()


def refine_strings(s, most_common_words=most_common_words, invalid_pattern=invalid_pattern):
    """
    It proprocesses the given string using the function above and then split it to get a list of words and apply some filter on this list
    :param s:string
    :param most_common_words:
    :param invalid_pattern:
    :return: a list of refined strings created from the given strings
    """
    preprocessed_str = preprocess_string(s)
    new_list = preprocessed_str.split()
    filtered_list = [ix for ix in new_list if ((len(ix) >= 5) and (ix.lower() not in most_common_words) and (
            re.fullmatch(invalid_pattern, ix.lower()) is None) and (not ix.startswith('0x')) and (
                                                       re.fullmatch(floating_num_pattern, ix.lower()) is None) and (
                                                   not ix.startswith('__')))]
    return filtered_list


def valid_differenting_function(s, most_common_words=most_common_words, invalid_pattern=invalid_pattern):
    """
    It proprocesses the given string using the function above and then split it to get a list of words and apply some filter on this list
    :param s: string
    :param most_common_words:
    :param invalid_pattern:
    :return: True/False
    """
    return ((len(s) >= 5) and (s.lower() not in most_common_words) and (
            re.fullmatch(invalid_pattern, s.lower()) is None) and (not s.startswith('0x')) and (
                    re.fullmatch(floating_num_pattern, s.lower()) is None) and (not s.startswith('__')))


def is_ignored_file(file_path):
    ext_uz = file_path.split('.')[-1]
    if (ext_uz.lower() in EXT_TO_IGNORE):
        return True

    ignore_path = 0
    for p_ignore in PATHS_TO_IGNORE:
        if p_ignore in file_path.lower():
            ignore_path = 1
            break

    if ignore_path:
        return True

    return False


def is_interested_file(file_path):
    cmd_file = 'file \"%s\"' % file_path
    result_file = exec_command(cmd_file)

    for int_ext in INTERESTED_FILE_TYPE:
        '''from the file output, remove the original file name'''
        if int_ext in str(result_file['output']).replace(file_path.split('/')[-1], ''):
            return True
        elif int_ext.lower() in str(result_file['output']).replace(file_path.split('/')[-1], '').lower():
            return True
    return False


def get_binary_pkg_name(file_path):
    pkg_name = file_path
    if '.deb' in file_path or '.rpm' in file_path:
        pkg_name = [fi for fi in file_path.split('/') if '.deb' in fi or '.rpm' in fi][0]
        if 'extracted' in pkg_name:
            pkg_name = pkg_name.replace('.extracted', '')[1:]
    elif '/lib/modules/' in file_path:
        tmp_fname = file_path.split('/lib/modules/')[-1]
        if len(tmp_fname.split('/')) > 1:
            pkg_name = tmp_fname.split('/')[0]
    elif '/usr/lib/' in file_path:
        tmp_fname = file_path.split('/usr/lib/')[-1]
        if len(tmp_fname.split('/')) > 1:
            pkg_name = tmp_fname.split('/')[0]
    return pkg_name


def get_meta_info(file_path):
    cmd = 'exiftool -j \"%s\"' % file_path
    result = exec_command(cmd)
    if 'error' in result:
        print("get_meta_info|Error in exiftool, error=%s, file=%s", result, file_path)
        return {}
    try:
        return json.loads(result['output'])[0]
    except Exception as e:
        print("get_meta_info|Error in exiftool, error=%s, file=%s", e, file_path)
        return {}


def get_pkgstrings(pkg_path):
    pkg_text = strings_cmd(pkg_path)
    if 'error' in pkg_path:
        return pkg_text
    filetexttokens = []
    for phrase in pkg_text['cmd_output']:
        phrase_decode = phrase.decode('ascii')
        '''remove dynamically linked libraries'''
        if '.so.' in str(phrase_decode).lower():
            continue
        filetexttokens.append(str(phrase_decode))
    filetext = "\n".join(filetexttokens)
    return filetext


def _check_for_busybox(filetext):
    res = re.search("BusyBox v+([\d\.\d\w-]+) \(", filetext)
    ver = ''
    if res != None:
        ver = res.groups(0)[0]
    return ver


def _get_linux_ver(filetext, all_ver):
    res = re.search("Linux version ([\d\.\d\w-]+)", filetext)
    print('Binary engine:: get_linux_ver|len(all_ver)=%s', str(len(all_ver)))
    if res != None:
        print('Binary engine:: get_linux_ver|res.groups=%s', str(res.groups(0)[0]))
        matched_vers = []
        ver_ori = res.groups(0)[0]
        for ver in all_ver:
            if ver == '' or len(ver.split('.')) == 1:
                continue
            if ver == '1.0' or ver == '2.0' or ver == '3.0' or ver == '4.0' or ver == '5.0' or ver.count('.') == 0:
                continue
            ver_items = ver.split(':')
            ver_items = [it for it in ver_items if ('x86' not in it) and ('64' not in it)]
            if len(ver_items) > 2:
                ver = '-'.join(ver_items[:2])
            else:
                ver = '-'.join(ver_items)
            ver = ver.replace('--', '-')
            ver = ver.replace('####', '-')
            # app.logger.info('get_linux_ver|ver=%s, ver_ori=%s', str(ver), str(ver_ori))
            if ver == ver_ori:
                matched_vers.append(ver)
            else:
                '''
                remove any patch component in from the version string and do the matching
                if there is a match, we need to reduce the mathcing confidence
                '''
                if ver == ver_ori.split('-')[0]:
                    matched_vers.append(ver)
        if len(matched_vers) > 0:
            print('Binary engine:: get_linux_ver|matched_vers=%s', str(matched_vers))
            return sorted(matched_vers)[-1]
        else:
            return ver_ori
    else:
        return ''


def _get_binutils_ver(filetext):
    res = re.search("\(GNU Binutils\) ([\d\.\d\w-]+)", filetext)
    if res != None:
        return res.groups(0)[0]
    else:
        return ''


# def _check_for_zlib(filetext):
#     is_zlib = False
#     '''statically linked lib'''
#     '''
#     if 'ZLIB_' in filetext:
#         is_zlib = True
#     '''
#     ver = ''
#     if ('Jean-loup Gailly' in filetext) and ('Mark Adler' in filetext):
#         is_zlib = True
#
#     '''
#     REVIEW:: review the zlib detection logic
#     '''
#     if is_zlib:
#         res = re.search("deflate ([\d\.\d\w-]+)", filetext)
#         if res != None:
#             ver = res.groups(0)[0]
#         res = re.search("inflate ([\d\.\d\w-]+)", filetext)
#         if res != None:
#             ver = res.groups(0)[0]
#
#         if ver != '' and len(ver.split('.')) > 1:
#             return 'zlib|gnu|' + ver
#         else:
#             res = _match_version_in_binary('zlib|gnu', filetext)
#
#             if len(res) > 0:
#                 return natsorted(res)[-1]
#             else:
#                 return 'zlib|gnu'
#
#     return None


# def _match_version_in_binary(lib_vend_name, filetext):
#     prod_vend_list_non_ver_temp = []
#     matched_lib = lib_vend_name.split('|')[0]
#     matched_vendor = lib_vend_name.split('|')[1]
#     all_ver_tmp = get_lib_vers(lib_name=matched_lib, vendor_name=matched_vendor, platform='NOT_SPECIFIED')
#     if all_ver_tmp:
#         all_ver_ori = [v for v in all_ver_tmp if v]
#     else:
#         all_ver_ori = []
# 
#     print("\n\nBinary engine::  match_version_in_binary, ver_list len=%s filetext len=%s\n\n",
#                      str(len(all_ver_ori)), str(len(filetext.split('\n'))))
#     '''
#     REVIEW:: only take the last 1000 versions
#     '''
#     all_ver = []
#     if len(all_ver_ori) > 1000:
#         # all_ver = natsorted(all_ver_ori)[-500:]
#         '''
#         REVIEW:: take last 5 versions
#         '''
#         all_ver = natsorted(all_ver_ori)[-5:]
#     else:
#         all_ver = all_ver_ori
#     print("\n\nBinary engine:: match_version_in_binary, after filtering ver_list len=%s\n\n",
#                      str(len(all_ver)))
# 
#     for ver_tmp in all_ver:
#         if not ver_tmp:
#             continue
#         ver_tmp = ver_tmp.replace('####', '-')
#         ver_tmp = ver_tmp.replace('-release', '')
#         ver_tmp = ver_tmp.split('-')[0]
#         query = r".*" + re.escape(ver_tmp) + r".*"
#         matches = re.findall(query, filetext)
#         if len(matches) > 0:
#             for matched_ver in matches:
#                 '''
#                 REVIEW:: avoid matching version number from dynamically loaded llibraries
#                 '''
#                 if (ver_tmp in matched_ver) and ('.so.' not in matched_ver) and (
#                         matched_ver.count('.') >= ver_tmp.count('.')) and ver_tmp.count('.') > 0:
#                     libvenver = lib_vend_name + '|' + ver_tmp
#                     prod_vend_list_non_ver_temp.append(libvenver)
# 
#     print("\n\nBinary engine:: match_version_in_binary, matched libvendver=%s\n\n",
#                      str(natsorted(list(set(prod_vend_list_non_ver_temp)))))
#     return prod_vend_list_non_ver_temp

#
# def _get_libpng_ver(filetext):
#     res = re.search("libpng version ([\d\.\d\w-]+) ", filetext)
#     ver = ''
#     if res != None:
#         ver = res.groups(0)[0]
#
#     if ver != '' and len(ver.split('.')) > 1:
#         all_ver = get_lib_vers(lib_name='libpng', vendor_name='libpng', platform='NOT_SPECIFIED')
#         if ver in all_ver:
#             return 'libpng|libpng|' + ver
#         else:
#             return None
#     return None


def _check_for_libpcap(filetext):
    is_libpcap = False
    if 'libpcap version' in filetext.lower():
        is_libpcap = True
    return is_libpcap

def strings_cmd(input_file):
    # cmd     = 'strings -7 \"%s\" | grep -E -i "^([-a-z0-9_]+\.[-a-z0-9_]*)+$"' % input_file
    # cmd     = 'strings -7 \"%s\" | grep -E -i "([-a-z0-9_]+\.[-a-z0-9_]*)+"' % input_file
    try:
        cmd = 'upx -d \"%s\"' % input_file
        result = exec_command(cmd)
    except:
        pass
    cmd = 'strings \"%s\"' % input_file
    result = exec_command(cmd)
    if 'error' in result:
        print('Binary engine:: Error in strings_cmd() cmd=%s, error msg=%s', cmd, result)
        return result
    cmd_output = result['output'].splitlines()
    raw_content = set()
    content_vector = set()

    '''
    REVIEW:: No need additional pre-processing of signatures
    '''
    '''
    for phrase in cmd_output:
        phrase = phrase.decode()
        for word in phrase.strip().split(" "):
            raw_content.update([word])
        if '^' not in phrase and '`' not in phrase:
            sanitized_phrase = re.sub(r'[\+,\/\_\:\\]+', ' ', phrase)
            content_vector.update([sanitized_phrase.strip().lower(), phrase.strip().lower()])
    '''

    '''
    app.logger.debug('\nBinary engine:: strings_cmd|input_file=%s, len cmd_output=%s file_content=%s, file_content_raw=%s \n',
                    input_file, str(len(cmd_output)), str(len(content_vector)), str(len(raw_content)))
    '''
    return {'cmd_output': cmd_output, 'file_content': content_vector, 'file_content_raw': raw_content}


