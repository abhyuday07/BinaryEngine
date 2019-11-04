
"""parameters for feature extraction"""
string_length_threshold = 5
func_length_threshold = 5
string_array_length_threshold = 8
const_num_array_length_threshold = 10
const_enum_array_length_threshold = 10

"""parameter for bloom filter"""
bloom_filter_volume = 2 ** 16
bloom_filter_error_rate = 0.01

"""parameter for mongodb"""
db_host = 'ec2-18-138-229-211.ap-southeast-1.compute.amazonaws.com'
db_port = 27017
db_feature = 'Binary_Engine_Feature'
db_test_data = 'Binary_Engine_Test_Data'
db_test_collection = "test_data"
db_fn_collection = 'fn'
db_1g_collection = '1g'
db_2g_collection = '2g'
db_3g_collection = '3g'
db_string_array_collection = 'string_arrays'
db_const_num_array_collection = 'const_num_arrays'
db_const_enum_array_collection = 'const_enum_arrays'
db_batch_size = 100
db_core = 8

"""parameter for predictor with strings"""
feature_fn_weights = 8.5
feature_1g_weights = 1
feature_2g_weights = 2.5
feature_3g_weights = 20

"""parameter for predictor with string_arrays"""
string_array_max_ratio = 0.08

"""parameter for predictor with const_num_arrays"""
const_num_array_max_ratio = 0.1

"""parameter for predictor with const_enum_arrays"""
const_enum_array_max_ratio = 0.1

"""parameter for test dataset size"""
test_data_length = 1000

"""parameter for feature extraction from source code"""
extracted_feature_types = ["const_num_arrays", "const_enum_arrays", "string_arrays", "strings", "func_names"]
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
global_file_feature = {'strings': [],
                       'func_names': [],
                       'string_arrays': [],
                       'ori_const_num_arrays': [],
                       'const_num_arrays': [],
                       'const_enum_arrays': [],
                       'ori_const_enum_arrays': [],
                       'const_enum_typedefs': {},
                       'const_num_array_typedefs': {}}




