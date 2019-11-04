import sys

import _pickle as cPickle
import concurrent.futures
import pymongo
from collections import defaultdict
import utils
import Levenshtein
from bloom_filter import BloomFilter
import sys
sys.path.append('/home/wufeng/B2S/B2SFinder/Generate_Feature_to_DB')
import config

class MongoDB_Sync():
    def __init__(self):
        """
        :param db_name:
        :param collection_name:
        """
        self.host = config.db_host
        self.port = config.db_port
        self.db_name = config.db_feature
        self.client = pymongo.MongoClient(self.host, port=self.port)
        self.db = self.client[self.db_name]
        self.collection = {}
        self.collection[config.db_fn_collection] = self.db[config.db_fn_collection]
        self.collection[config.db_1g_collection] = self.db[config.db_1g_collection]
        self.collection[config.db_2g_collection] = self.db[config.db_2g_collection]
        self.collection[config.db_3g_collection] = self.db[config.db_3g_collection]
        self.collection[config.db_string_array_collection] = self.db[config.db_string_array_collection]
        self.collection[config.db_const_num_array_collection] = self.db[config.db_const_num_array_collection]
        self.collection[config.db_const_enum_array_collection] = self.db[config.db_const_enum_array_collection]

    def do_query(self, feature_data, collection_ids, skip_n, limit_n, batch_size):
        """
        :param feature_data: {'fn': [str1, str2, ...], '1g':[str1, str2, ...], ...}
        :param collection_ids: ['fn', '1g', '2g', '3g']
        :return: {'lib_id_1': XXX, 'XXX_string_feature':[feature_1, feature_2, ...],
                  'lib_id_2': XXX, 'XXX_string_feature':[feature_1, feature_2, ...],
                  ...}

        :param feature_data: {'string_array':[str_list_1, str_list_2, str_list_3, ...]}
        :param collection_ids: ['string_array']
        :return: {'lib_id_1': XXX, 'XXX_string_array_feature':{'score':[float1, float2, float3, ...]
                                                                'source_item':[str_list_1, str_list_2, ...]
                                                                'binary_item':[str_list_1, str_list_2, ...]},
                 'lib_id_2': XXX, 'XXX_string_array_feature':{'score':[float1, float2, float3, ...]
                                                                'source_item':[str_list_1, str_list_2, ...]
                                                                'binary_item':[str_list_1, str_list_2, ...]},
                                                                ...}
        :param feature_data: {'const_num_array':[unknown_list_1, unknown_list_2, unknown_list_3, ...]}
        :param collection_ids: ['const_num_array']
        :return:{'lib_id_1': XXX, 'XXX_const_num_array_feature':{'matched_count':int
                                                                'total_count':int},
                 'lib_id_2': XXX, 'XXX_const_num_array_feature':{'matched_count':int
                                                                'total_count':int},
                                                                ...}
        :param feature_data: {'const_enum_array':[unknown_list_1, unknown_list_2, unknown_list_3, ...]}
        :param collection_ids: ['const_enum_array']
        :return:{'lib_id_1': XXX, 'XXX_const_enum_array_feature':{'matched_count':[int, int, ...]
                                                                'total_count':[int, int, ...]
                                                                'binary_file_count':[int]},
                 'lib_id_2': XXX, 'XXX_const_enum_array_feature':{'matched_count':[int, int, ...]
                                                                'total_count':[int, int, ...]
                                                                'binary_file_count':[int]},
                                                                ...}
        :param skip_n:
        :param limit_n:
        :param batch_size:
        """
        if collection_ids == [config.db_fn_collection, config.db_1g_collection, config.db_2g_collection, config.db_3g_collection]:
            print('[++DB process++]starting process string feature in DB', skip_n//limit_n, '...')
            result = {}
            for type in collection_ids:
                cursor = self.collection[type].find({}, batch_size=batch_size).skip(skip_n).limit(limit_n)
                string_features = feature_data.get(type)
                for document in cursor:
                    document.pop('_id')
                    lib_id_model = list(document.items())[0]
                    lib_id = lib_id_model[0]
                    model = lib_id_model[1]
                    bf = cPickle.loads(model)
                    result[lib_id + 'string_feature' + '_' + type] = [feature for feature in string_features if feature in bf]
            return result

        if collection_ids == [config.db_string_array_collection]:
            print('[++DB process++]starting process string array in DB', skip_n // limit_n, '...')
            result = {}
            cursor = self.collection[config.db_string_array_collection].find({}, batch_size=batch_size).skip(skip_n).limit(limit_n)
            binary_string_arrays = feature_data.get(config.db_string_array_collection)
            for document in cursor:
                document.pop('_id')
                lib_id_model = list(document.items())[0]
                lib_id = lib_id_model[0]
                feature = lib_id_model[1]
                source_string_arrays = []
                for string_arr in feature:
                    source_string_arrays.extend(string_arr['array'])
                string_array_matched_result = match_string_array(source_string_arrays, binary_string_arrays)
                result[lib_id + config.db_string_array_collection] = string_array_matched_result
            return result

        if collection_ids == [config.db_const_num_array_collection]:
            print('[++DB process++]starting process const num array in DB', skip_n // limit_n, '...')
            result = {}
            cursor = self.collection[config.db_const_num_array_collection].find({}, batch_size=batch_size).skip(skip_n).limit(limit_n)
            binary_bytes_list = feature_data.get(config.db_const_num_array_collection)
            for document in cursor:
                document.pop('_id')
                lib_id_model = list(document.items())[0]
                lib_id = lib_id_model[0]
                feature = lib_id_model[1]
                const_num_arrays = []
                for const_num_array in feature:
                    if 'element_type' in const_num_array.keys():
                        const_num_arrays.append(const_num_array)
                # print(const_num_arrays)
                const_num_array_matched_result = match_const_num_array(binary_bytes_list, const_num_arrays)
                if len(const_num_array_matched_result) != 0:
                    result[lib_id + config.db_const_num_array_collection] = const_num_array_matched_result
            return result

        if collection_ids == [config.db_const_enum_array_collection]:
            print('[++DB process++]starting process const enum array in DB', skip_n // limit_n, '...')
            result = {}
            cursor = self.collection[config.db_const_enum_array_collection].find({}, batch_size=batch_size).skip(skip_n).limit(limit_n)
            binary_bytes_list = feature_data.get(config.db_const_enum_array_collection)
            for document in cursor:
                document.pop('_id')
                lib_id_model = list(document.items())[0]
                lib_id = lib_id_model[0]
                feature = lib_id_model[1]
                const_enum_arrays = []
                for const_enum_array in feature:
                    if 'element_type' in const_enum_array.keys():
                        const_enum_arrays.append(const_enum_array)
                const_enum_array_matched_result = match_const_enum_array(binary_bytes_list, const_enum_arrays)
                if len(const_enum_array_matched_result) != 0:
                    result[lib_id + config.db_const_enum_array_collection] = const_enum_array_matched_result
            return result

    def multi_process_query(self, collection_ids, n_cores, feature_data, batch_size):
        """
        :param type:
        :param n_cores:
        :param string_features:
        :return:
        """
        collection_size = self.do_count(type=collection_ids[0])
        if batch_size > collection_size:
            n_cores = 1
            limit_length = collection_size
        else:
            limit_length = round(collection_size/n_cores + 0.5)
            if limit_length < 1:
                limit_length = 1
        skips = range(0, n_cores*limit_length, limit_length)
        feature_result = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_cores) as executor:
            # future: name
            result_name = {executor.submit(self.do_query, feature_data, collection_ids, skip, limit_length, batch_size): skip for skip in skips}
            for future in concurrent.futures.as_completed(result_name):
                for key in future.result(result_name):
                    feature_result[key] = future.result(result_name)[key]
        return feature_result

    def do_count(self, type):
        """
        # count the number of documents in mongoDB
        :return:
        """
        return self.collection[type].count_documents({})

    def do_add_strings(self, string_lists):
        try:
            for key in string_lists:
                document = {}
                bf = BloomFilter(max_elements=2 ** 16, error_rate=0.01)
                [bf.add(element) for element in string_lists.get(key)]
                bf_pickle = cPickle.dumps(bf)
                document[key] = bf_pickle
                sig = key.split('_')
                for type in self.collection:
                    if type == sig[len(sig) - 1]:
                        size = sys.getsizeof(document[key])
                        print("asynic save bloom tree into mongDB: %s \t size is %f" % (key, size / 1024 / 1024))
                        break
        except Exception as e:
            print(e)

def match_string_array(source_string_arrays, binary_string_arrays):
    """
    :param source_string_arrays: [str_list_1, str_list_2, str_list_3, ...]
    :param binary_string_arrays: [str_list_1, str_list_2, str_list_3, ...]
    :return:
    """
    final_result = defaultdict(list)
    for source_item in source_string_arrays:
        source_item = utils.code_preprocess(source_item)
        tmp_result = defaultdict(list)
        for binary_item in binary_string_arrays:
            score = Levenshtein.jaro_winkler(source_item, binary_item)
            if score > 0.65:
                tmp_result["score"].append(score)
                tmp_result["binary_item"].append(binary_item)
                tmp_result["source_item"].append(source_item)
        if len(tmp_result) > 0:
            score_index = tmp_result['score'].index(max(tmp_result['score']))
           # print("source_string_item can be found in binary_file, score is %f.\n\t source_item:%s \n\t binary_item: %s" % (
          #  max(tmp_result['score']), source_item, tmp_result['binary_item'][score_index]))
            final_result["score"].append(max(tmp_result['score']))
            final_result["source_array"].append(tmp_result['source_item'][score_index])
            final_result['binary_array'].append(tmp_result['binary_item'][score_index])
    return final_result


def match_const_num_array(binary_bytes_list, source_const_num_arrays):
    """
    :param source_const_num_arrays: [unknown_list_1, unknown_list_2, ...]
    :param binary_bytes_list: b'[0xfE0x010x02...]----[00001110011000010000111]
    :return:
    """
    final_result = defaultdict(list)
    uprepeat_const_num_array = utils.get_hex_search_list(source_const_num_arrays, lib_name="tmp")
    if len(uprepeat_const_num_array) == 0:
        return final_result
    for binary_bytes in binary_bytes_list:
        matched_count, total_count = utils.compare_arr2dll(binary_bytes, uprepeat_const_num_array, use_score=True)
        final_result['matched_count'].append(matched_count)
        final_result['total_count'].append(total_count)
    final_result['binary_files_count'] = [len(binary_bytes_list)]
    return final_result


def match_const_enum_array(binary_bytes_list, source_const_enum_arrays):
    """
    :param source_const_enum_arrays: [unknown_list_1, unknown_list_2, ...]
    :param binary_bytes: b'[0xfE0x010x02...]----[00001110011000010000111]
    :return:
    """
    final_result = defaultdict(list)
    uprepeat_const_enum_array = utils.get_hex_search_list(source_const_enum_arrays, lib_name="tmp")
    if len(uprepeat_const_enum_array) == 0:
        return final_result
    for binary_bytes in binary_bytes_list:
        matched_count, total_count = utils.compare_arr2dll(binary_bytes, uprepeat_const_enum_array, use_score=True)
        final_result['matched_count'].append(matched_count)
        final_result['total_count'].append(total_count)
    final_result['binary_files_count'] = [len(binary_bytes_list)]
    return final_result

    # def do_delete_many(self, documents):
    #     """
    #     # delete documents in collections of mongoDB
    #     :param documents:
    #     :return:
    #     """
    #     for type in self.collection:
    #         self.collection[type].delete_many(documents)

    # def do_replace(self, id, document):
    #     """
    #     # replace the content of OBjectID in mongoDB
    #     :param id:
    #     :param document:
    #     :return:
    #     """
    #     for type in self.collection:
    #         old_document = self.collection[type].find()
    #         _id = old_document['_id']
    #         self.collection[type].replace_one({'_id': _id}, document)


# class mongodb_asynic():
#
#     def __init__(self, host, username, password, port, authSource, db_name, collection_name):
#         self.host = host
#         self.username = username
#         self.password = password
#         self.port = port
#         self.authSource = authSource
#         self.db_name = db_name
#         self.collection_name = collection_name
#         self.client = motor.motor_asyncio.AsyncIOMotorClient(
#             'mongodb://%s:%s@%s:%s' % (self.username, self.password, self.host, self.port))
#         self.db = self.client[self.db_name]
#         self.collection = {}
#         self.collection['fn'] = self.db[self.collection_name + '_fn']
#         self.collection['1g'] = self.db[self.collection_name + '_1g']
#         self.collection['2g'] = self.db[self.collection_name + '_2g']
#         self.collection['3g'] = self.db[self.collection_name + '_3g']
#
#     async def do_drop(self):
#         for type in self.collection:
#             await  self.collection[type].drop()
#
#     async def do_add(self, string_lists):
#         try:
#             for key in string_lists:
#                 document = {}
#                 bf = BloomFilter(max_elements=2 ** 16, error_rate=0.01)
#                 [bf.add(element) for element in string_lists.get(key)]
#                 bf_pickle = cPickle.dumps(bf)
#                 document[key] = bf_pickle
#                 sig = key.split('_')
#                 for type in self.collection:
#                     if type == sig[len(sig) - 1]:
#                         size = sys.getsizeof(document[key])
#                         await self.collection[type].insert_one(document=document)
#                         print("asynic save bloom tree into mongDB: %s \t size is %f" % (key, size / 1024 / 1024))
#                         break
#         except Exception as e:
#             print(e)
#
#     async def do_count(self):
#         sum = 0
#         for type in self.collection:
#             sum += await self.collection[type].count_documents({})
#         return sum
#
#     async def do_query(self, string_features, document_count):
#         result = {}
#         for type in self.collection:
#             cursor = self.collection[type].find({})
#             for document in await cursor.to_list(document_count):
#                 index = 0
#                 for key in document:
#                     if index == 1:
#                         bf_pickle = document.get(key)
#                         bf = cPickle.loads(bf_pickle)
#                         count = 0
#                         for feature in string_features:
#                             if feature in bf:
#                                 count += 1
#                         result[key] = count
#                     index += 1
#         return result

#
# if __name__ == '__main__':
#     # load json_file to CPU Memory
#     file_path = '/home/wufeng/Downloads/bt_dict.json'
#     file_read = open(file_path, 'r')
#     file_json = json.load(file_read)
#     test_path = '/home/wufeng/Downloads/test.txt'
#     test_strings = []
#     with open(test_path, 'r') as test_read:
#         for line in test_read.readlines():
#             test_strings.append(line.split(',')[0].split('\"')[1])
#     print(test_strings)
#
#     mongodb_synic = mongodb_synic(host='localhost', username='root', password='example', port=27018, authSource='admin',
#                                   db_name='new_synic_bloom_filter', collection_name='filters')
#     mongodb_synic.do_drop()
#     start_time = time.time()
#     mongodb_synic.do_add(file_json)
#     print("write files, size 0.15M / file, time is %f" % (time.time() - start_time))
#     start_time = time.time()
#     result = mongodb_synic.do_query(test_strings)
#     print("find_result \n %s" % result)
#     print("query time is :%f" % (time.time() - start_time))
#
#     mongodb_asynic = mongodb_asynic(host='localhost', username='root', password='example', port=27018,
#                                     authSource='admin',
#                                     db_name='new_asynic_bloom_filter', collection_name='filters')
#     loop = asyncio.get_event_loop()
#     loop.run_until_complete(mongodb_asynic.do_drop())
#     start_time = time.time()
#     loop.run_until_complete(mongodb_asynic.do_add(file_json))
#     print("write files, size 0.15M / file, time is %f" % (time.time() - start_time))
#     start_time = time.time()
#     document_count = loop.run_until_complete(mongodb_asynic.do_count())
#     result = loop.run_until_complete(mongodb_asynic.do_query(test_strings, document_count))
#     print("find_result \n %s" % result)
#     print("query time is :%f" % (time.time() - start_time))
