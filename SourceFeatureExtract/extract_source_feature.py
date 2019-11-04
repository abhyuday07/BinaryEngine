# -*- coding: utf-8 -*-

import sys

sys.path.append('..')
from clang.cindex import Config
from clang.cindex import CursorKind
from clang.cindex import Index
from clang.cindex import TokenKind
from src_proj_preprocessor import *
from collections import defaultdict
import sys
sys.path.append('/home/wufeng/B2S/B2SFinder/DB')
sys.path.append('/home/wufeng/B2S/B2SFinder/Generate_Feature_to_DB')
import mongoDB
import config

global global_file_feature
global_file_feature = config.global_file_feature


def clean_global_file_feature():
    global global_file_feature
    global_file_feature =config.global_file_feature


def construct_AST(file_path, compile_options=[]):
    index = Index.create()
    tu = index.parse(file_path, compile_options)
    return tu.cursor


def iter_cursor_content(cur):
    cursor_content = ""
    for token in cur.get_tokens:
        if token.kind != TokenKind.COMMENT:
            str_token = token.spelling + " "
            cursor_content = cursor_content + str_token
    return cursor_content


def analyze_INIT_LIST_EXPR(cursor):
    for cur_sub in cursor.get_children():
        if cur_sub.kind == CursorKind.INIT_LIST_EXPR:
            is_const_num_array = analyze_INIT_LIST_EXPR(cur_sub)
            if not is_const_num_array:
                return False
        if cur_sub.kind not in [CursorKind.INTEGER_LITERAL,
                                CursorKind.UNEXPOSED_EXPR,
                                CursorKind.INIT_LIST_EXPR,
                                CursorKind.BINARY_OPERATOR,
                                CursorKind.UNARY_OPERATOR,
                                CursorKind.COMPOUND_ASSIGNMENT_OPERATOR]:
            return False
        if cur_sub.kind == CursorKind.UNEXPOSED_EXPR:
            for cur_subsub in cur_sub.get_children():
                if cur_subsub.kind not in [CursorKind.INTEGER_LITERAL,
                                           CursorKind.UNARY_OPERATOR,
                                           CursorKind.COMPOUND_ASSIGNMENT_OPERATOR]:
                    return False
    return True


def get_array_value(cursor, large_list=False):
    cursor_content = ""
    if not large_list:
        for token in cursor.get_tokens():
            if token.cursor.kind == CursorKind.INTEGER_LITERAL or token.cursor.kind == CursorKind.UNARY_OPERATOR:
                str_token = token.spelling + ""
                cursor_content = cursor_content + str_token
            elif token.cursor.kind == CursorKind.INVALID_FILE:
                print("[ERROR] CursorKind.INVALID_FILE in get_array_value")
                break
    else:
        value_str = iter_cursor_content(cursor)
        cursor_content = value_str.replace(",", " ").replace("{", " ").replace("}", " ")
    return cursor_content


def convert_str_to_int(value_str):
    if 'h' in value_str or 'H' in value_str:
        value_str = value_str.replace('h', ' ').replace('H', ' ')
        return int(value_str, 16)
    if 'u' in value_str or 'U' in value_str or 'l' in value_str or 'L' in value_str:
        value_str = value_str.replace('u', ' ').replace('U', ' ').replace('l', ' ').replace('L', ' ')
    try:
        return int(value_str)
    except:
        try:
            return int(value_str, 16)
        except:
            print("[ERROR] cannot convert str to int:", value_str)
            return None


def get_const_num_arr_value(cursor, num_array, large_list=False):
    children_count = sum([1 for _ in cursor.get_children()])
    for cur in cursor.get_children():
        if cur.kind == CursorKind.INTEGER_LITERAL or cur.kind == CursorKind.UNARY_OPERATOR:
            value_str = get_array_value(cur, large_list)
            if value_str == "":
                return None
            value = convert_str_to_int(value_str)
            num_array.append(value)
        else:
            num_array = get_const_num_arr_value(cur, num_array, large_list)
            if num_array is None:
                return None
    return num_array


def get_const_number_array_value(cursor):
    num_arr = []
    get_num_arr = []
    for cur_sub in cursor.get_children():
        if cur_sub.kind == CursorKind.INIT_LIST_EXPR:
            list_length = sum([1 for _ in cur_sub.get_children()])
            if list_length > 1000:
                num_arr = get_const_num_arr_value(cur_sub, get_num_arr, True)
            else:
                num_arr = get_const_num_arr_value(cur_sub, get_num_arr, False)
    return num_arr


def extract_const_number_array(root_cursor):
    global global_file_feature
    for cur in root_cursor.get_children():
        if cur.kind == CursorKind.TYPEDEF_DECL:
            global_file_feature['const_num_array_typedefs'][cur.spelling] = cur.underlying_typedef_type.spelling
    for cursor in root_cursor.get_children():
        if cursor.kind == CursorKind.VAR_DECL and cursor.spelling != "":
            addit = False
            for cur_sub in cursor.get_children():
                if cur_sub.kind == CursorKind.INIT_LIST_EXPR:
                    addit = analyze_INIT_LIST_EXPR(cur_sub)
                    if cursor.type.get_array_element_type().spelling == "":
                        addit = False
            if addit:
                num_array = get_const_number_array_value(cursor)
                if num_array and None not in num_array:
                    global_file_feature['ori_const_num_arrays'].append(
                        {"array": num_array, "element_type": cursor.type.element_type.spelling,
                         "var_name": cursor.spelling})

    # local but static
    for cursor in root_cursor.get_children():
        if cursor.kind == CursorKind.FUNCTION_DECL or cursor.kind == CursorKind.CXX_METHOD:
            find_INIT_LIST_EXPR_from_function(cursor)
        elif cursor.kind == CursorKind.CLASS_DECL or cursor.kind == CursorKind.CLASS_TEMPLATE:
            for sub_cur in cur.get_children():
                if sub_cur.kind == CursorKind.FUNCTION_DECL or sub_cur.kind == CursorKind.CXX_METHOD:
                    find_INIT_LIST_EXPR_from_function(sub_cur)


def find_INIT_LIST_EXPR_from_function(func_cursor):
    for cursor in func_cursor.get_children():
        if cursor.kind == CursorKind.COMPOUND_STMT:
            for cur_sub in cursor.get_children():
                find_INIT_LIST_EXPR(cur_sub)


def find_INIT_LIST_EXPR(cursor):
    for cur_sub in cursor.get_children():
        if cur_sub.kind == CursorKind.INIT_LIST_EXPR:
            addit = analyze_INIT_LIST_EXPR(cur_sub)

            if cursor.type.get_array_element_type().spelling == "":
                addit = False

            if addit:
                num_array = get_const_number_array_value(cursor)
                if num_array and None not in num_array:
                    global_file_feature['ori_const_num_arrays'].append(
                        {"array": num_array, "element_type": cursor.type.element_type.spelling,
                         "var_name": cursor.spelling})
        else:
            find_INIT_LIST_EXPR(cur_sub)


def extract_string_array(cursor):
    global global_file_feature
    if cursor.kind == CursorKind.VAR_DECL:
        string_array_list = []
        addit = False
        for cur_sub in cursor.get_children():
            if cur_sub.kind == CursorKind.INIT_LIST_EXPR:
                for cur_subsub in cur_sub.get_children():
                    if cur_subsub.kind == CursorKind.STRING_LITERAL:
                        string_array_list.append(cur_subsub.spelling)
                        addit = True
        if addit:
            global_file_feature['string_arrays'].append({"array": string_array_list, "var_name": cursor.spelling})

    for kid_cursor in cursor.get_children():
        extract_string_array(kid_cursor)


def extract_const_enum_array(root_cursor):
    global global_file_feature
    for cursor in root_cursor.get_children():
        if cursor.kind == CursorKind.TYPEDEF_DECL:
            global_file_feature['const_enum_typedefs'][cursor.spelling] = cursor.underlying_typedef_type.spelling
        if cursor.kind == CursorKind.VAR_DECL:
            for cur in cursor.get_children():
                if cur.kind == CursorKind.INIT_LIST_EXPR:
                    item_list = []
                    for member in cur.get_children():
                        if member.kind == CursorKind.DECL_REF_EXPR:
                            ref = member.referenced
                            if ref.kind == CursorKind.ENUM_CONSTANT_DECL:
                                item_list.append(ref.enum_value)
                    if len(item_list) > 0:
                        global_file_feature['ori_const_enum_arrays'].append(
                            {"array": item_list, "element_type": cursor.type.element_type.spelling,
                             "var_name": cursor.spelling})


def strip_static_const(type):
    type_list = type.split(' ')
    type_l = []
    for i in type_list:
        if i == 'const':
            continue
        if i == 'static':
            continue
        type_l.append(i)
    new_type = ' '.join(type_l)
    return new_type


def generate_const_enum_array():
    global global_file_feature
    for item in global_file_feature['ori_const_enum_arrays']:
        long_type = strip_static_const(item['type'])
        if long_type in global_file_feature['const_enum_typedefs']:
            num_type = global_file_feature['const_enum_typedefs'][long_type]
        elif long_type in config.type_dict_64:
            num_type = long_type
        else:
            num_type = None
        global_file_feature['const_enum_arrays'].append(
            {'array': item['array'], 'element_type': num_type, 'var_name': item['var_name']})


def generate_const_number_array():
    global global_file_feature
    for item in global_file_feature['ori_const_num_arrays']:
        long_type = strip_static_const(item['type'])
        if long_type in global_file_feature['const_num_array_typedefs']:
            num_type = global_file_feature['const_num_array_typedefs'][long_type]
        elif long_type in config.type_dict_64:
            num_type = long_type
        else:
            num_type = None
        global_file_feature['const_num_arrays'].append(
            {'array': item['array'], 'element_type': num_type, 'var_name': item['var_name']})


def extract_hard_coded_strings(cursor):
    global global_file_feature
    for token in cursor.get_tokens():
        if token.kind.name == 'LITERAL':
            if token.spelling.endswith('\"') and len(token.spelling) > 2:
                if token.spelling[0] == '"' and token.spelling[-1] == '"':
                    global_file_feature['strings'].append(token.spelling[1:-1])
                elif token.spelling[0] == 'L"' and token.spelling[-1] == '"':
                    global_file_feature['strings'].append(token.spelling[2:-1])


def get_abs_filepath(path, base_path):
    if path[0] == "/":
        new_path = os.path.abspath(path)
    else:
        new_path = os.path.abspath(os.path.join(base_path, path))
    return new_path


def extract_func_names_core(cursor, project_root, base_path):
    global global_file_feature
    for cur in cursor.get_children():
        if cur.kind == CursorKind.FUNCTION_DECL or cur.kind == CursorKind.CXX_METHOD:
            if len(cur.spelling) and cur.is_definition() and project_root in get_abs_filepath(cur.location.file.name, base_path) and not cur.spelling.startswith("operator"):
                global_file_feature["func_names"].append(cur.spelling)
        elif cur.kind == CursorKind.CLASS_DECL or cur.kind == CursorKind.CLASS_TEMPLATE:
            for sub_cur in cur.get_children():
                if sub_cur.kind == CursorKind.FUNCTION_DECL or sub_cur.kind == CursorKind.CXX_METHOD:
                    if len(sub_cur.spelling) and sub_cur.is_definition() and project_root in get_abs_filepath(cur.location.file.name, base_path) and not sub_cur.spelling.startswith("operator"):
                        global_file_feature["func_names"].append(sub_cur.spelling)
        elif cur.kind == CursorKind.NAMESPACE:
            extract_func_names_core(cur, project_root, base_path)


def analysefile(file_path, file_compile_dir, compile_root, project_root, compile_options=[], feature_types=[]):
    global global_file_feature
    print("---------------------------------------------------------")
    print("[+] analyze file:", file_path, feature_types, compile_options)
    pyscript_dir = os.getcwd()  # save the working path ,after ananlyse we restore it
    clean_global_file_feature()

    # get compilation base path
    base_path = file_compile_dir
    if base_path is not None and compile_options is not None:
        for compile_option in compile_options:
            if compile_option.startswith("-I"):
                short_option = compile_option[2:].replace("/", " ").replace("\\", " ").replace(".", "").replace(" ", "")
                if not len(short_option):
                    continue
                if compile_root and os.path.exists(os.path.join(compile_root, compile_option[2:])):
                    base_path = compile_root
                    break
                elif project_root and os.path.exists(os.path.join(project_root, compile_option[2:])):
                    base_path = project_root
                    break
                elif os.path.exists(os.path.join(os.path.dirname(file_path), compile_option[2:])):
                    base_path = os.path.dirname(file_path)
                    break

    if base_path is None:
        base_path = compile_root
    if base_path is None:
        base_path = os.path.dirname(file_path)
    os.chdir(base_path)
    try:
        tmp_cursor = construct_AST(file_path, compile_options)
    except Exception as e:
        print("[construct_AST ERROR]", e)
        return None
    # include_list = get_include_list(tmp_cursor)
    print(tmp_cursor.get_tokens())
    for feature in feature_types:
        print("[-] extract " + feature, ":")
        try:
            if feature == "strings":
                extract_hard_coded_strings(tmp_cursor)
            elif feature == "func_names":
                global analyzed_header
                analyzed_header = []
                extract_func_names_core(tmp_cursor, project_root, base_path)
            elif feature == "const_num_arrays":
                extract_const_number_array(tmp_cursor)
                generate_const_number_array()
            elif feature == "string_arrays":
                extract_string_array(tmp_cursor)
            elif feature == "const_enum_arrays":
                extract_const_enum_array(tmp_cursor)
                generate_const_enum_array()
        except Exception as e:
            print("[ERROR]", e)
    os.chdir(pyscript_dir)
    return global_file_feature


def get_source_file_of_dir(project_root):
    c_files = []
    for parent, dirnames, filenames in os.walk(project_root):
        for filename in filenames:
            if filename.endswith(".c") or filename.endswith(".cpp") or filename.endswith(".cc") or filename.endswith(
                    ".cxx"):
                c_files.append(os.path.join(parent, filename))
    return c_files


def get_header_file_of_dir(project_root):
    h_files = []
    for parent, dirnames, filenames in os.walk(project_root):
        for filename in filenames:
            if filename.endswith(".h") or filename.endswith(".hpp"):
                h_files.append(os.path.join(parent, filename))
    return h_files


def analyze_project(project_root, feature_types):
    pre = Preprocessor(project_root)
    command_dict, need_to_compile_files, ori_bin_src_map, status, files_compile_dir = pre.get_make_info()

    # delete duplicate dynamic
    bin_src_map = {}
    for item in ori_bin_src_map:
        if not len(ori_bin_src_map[item]):
            continue
        if not len(bin_src_map):
            bin_src_map[item] = ori_bin_src_map[item]
            continue
        flag = True
        for bs_item in bin_src_map:
            if len(bin_src_map[bs_item]) != len(ori_bin_src_map[item]):
                continue
            u_len = len(set(bin_src_map[bs_item]) & set(ori_bin_src_map[item]))
            if u_len == len(bin_src_map[bs_item]):
                flag = False
                break
        if flag:
            bin_src_map[item] = ori_bin_src_map[item]

    if not len(need_to_compile_files) or not status:
        need_to_compile_files = get_source_file_of_dir(project_root)
        if not len(need_to_compile_files):  # all files are header file
            need_to_compile_files = get_header_file_of_dir(project_root)
        bin_src_map = {"fake_dynamic": need_to_compile_files}

    print("\nstart analyze files...")
    proj_features = {}
    for filepath in need_to_compile_files:
        filename = os.path.basename(filepath)

        file_compile_dir = None
        if filepath in files_compile_dir:
            file_compile_dir = files_compile_dir[filepath]

        compile_options = command_dict.get(filepath[len(project_root) + 1:])
        if compile_options is None:
            compile_options = command_dict.get("-" + filename)
        if compile_options is None:
            compile_options = ["-I."]
        needed_feature_types = []
        for ft in feature_types:
            if ft not in ["exports"]:
                needed_feature_types.append(ft)
        global_file_feature = analysefile(filepath, file_compile_dir, pre.compile_root, pre.path, compile_options,
                                          needed_feature_types)
        proj_features[filename] = global_file_feature
    return proj_features


py_cwd = os.getcwd()
clang_path = '/usr/lib/x86_64-linux-gnu/libclang.so '
libclang_path = '/usr/lib/x86_64-linux-gnu/libclang.so '


def download_url(url):
    tmp_path = os.path.join(os.getcwd(), 'source_tmp/')
    if not os.path.exists(tmp_path):
        os.system("mkdir %s" % tmp_path)
        # os.popen("sudo -S %s" % ("mkdir %s"%tmp_path), 'w').write('3141591990')
    else:
        os.system("rm -r %s" % tmp_path)
        os.system("mkdir %s" % tmp_path)
        # os.popen("sudo -S %s" % ("rm -r %s"%tmp_path), 'w').write('3141591990')
        # os.popen("sudo -S %s" % ("mkdir %s" % tmp_path), 'w').write('3141591990')
    print(url)
    print(tmp_path)
    os.system("wget -q -P %s %s" % (tmp_path, url))
    if len(os.listdir(tmp_path)) == 0:
        return 0
    file = os.listdir(tmp_path)[0]
    source_path = os.path.join(tmp_path, file)
    os.system("tar -zxvf %s -C %s" % (source_path, tmp_path))
    # os.popen("sudo -S %s" % ("tar -zxvf %s -C %s" %(source_path, tmp_path)), 'w').write('3141591990')
    os.system("rm %s" % source_path)
    # os.popen("sudo -S %s" % ("rm -r %s"%tmp_path), 'w').write('3141591990')
    return tmp_path


if __name__ == '__main__':
    mongoDB_sync = mongoDB.mongodb_synic(host=config.db_host,
                                         port=config.db_port,
                                         db_name=config.db_test_data,
                                         collection_name=config.db_test_collection)
    #db_save.do_drop()
    collection = mongoDB_sync.do_query()
    cursor = collection.find({})


    class SetEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, set):
                return list(obj)
            return json.JSONEncoder.default(self, obj)


    Config.set_library_file('/usr/lib/x86_64-linux-gnu/libclang.so')
    for document in cursor:
        document.pop('_id')
        for key in document:
            library_name = key
            source_urls = document[key]['source_code']
            binary_urls = document[key]['binary_code']
            result = {}
            content = {}
            content_level_2 = defaultdict(list)
            for version in source_urls:
                file_path = download_url(source_urls.get(version))
                if file_path == 0:
                    continue
                proj_features = analyze_project(file_path, config.extracted_feature_types)
                save_flag = False
                for item in proj_features:
                    for feature_type in config.extracted_feature_types:
                        if len(proj_features[item][feature_type]) != 0:
                            save_flag = True
                            break
                if save_flag:
                    content_level_2['source_code'].append(source_urls.get(version))
                    json_str = json.dumps(proj_features, cls=SetEncoder)
                    with open(os.path.join(os.getcwd(), 'output', '%s__%s.json' % (library_name, version)),
                              'w') as json_write:
                        json_write.write(json_str)
            if (content_level_2['source_code']) != 0:
                [content_level_2['binary_code'].append(binary_urls.get(ele)) for ele in binary_urls]
            content[key] = content_level_2
            # if len(content) != 0:
            #     db_save.do_add(content)
                # result[library_name + ":" + version] = proj_features
                # db_save.do_add(result)
