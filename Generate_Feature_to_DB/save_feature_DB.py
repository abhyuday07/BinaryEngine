import os
import json
from collections import defaultdict
import sys
sys.path.append('/home/wufeng/B2S/B2SFinder/DB')
import mongoDB
import _pickle as cPickle
from bloom_filter import BloomFilter
import config

base_dir = '../SourceFeatureExtract/output'
json_files = os.listdir(base_dir)
for file in json_files:
    with open(os.path.join(base_dir, file), 'r') as file_json_read:
        file_json = json.load(file_json_read)
        repo_features = defaultdict(list)
        print("process repo: library_name:%s\t version: %s"%(file.split('.json')[0].split('__')[0],file.split('.json')[0].split('__')[1]))
        for cpp_file in file_json:
            item = file_json[cpp_file]
            [repo_features['strings'].append(element) for element in item['strings'] if
             len(element) > config.string_length_threshold and len(item['strings']) > 0]
            [repo_features['func_names'].append(element) for element in item['func_names'] if
             len(element) > config.func_length_threshold and len(item['func_names']) > 0]
            [repo_features['string_arrays'].append(element) for element in item['string_arrays'] if
             len(element['array']) > config.string_array_length_threshold and len(item['string_arrays']) > 0]
            [repo_features['const_num_arrays'].append(element) for element in item['ori_const_num_arrays'] if
             len(element['array']) > config.const_num_array_length_threshold and len(item['ori_const_num_arrays']) > 0]
            [repo_features['const_num_arrays'].append(element) for element in item['const_num_arrays'] if
             len(element['array']) > config.const_num_array_length_threshold and len(item['const_num_arrays']) > 0]
            [repo_features['const_enum_arrays'].append(element) for element in item['ori_const_enum_arrays'] if
             len(element['array']) > config.const_enum_array_length_threshold and len(item['ori_const_enum_arrays']) > 0]
            [repo_features['const_enum_arrays'].append(element) for element in item['const_enum_arrays'] if
             len(element['array']) > config.const_enum_array_length_threshold and len(item['const_enum_arrays']) > 0]

        """build collection 'fn'"""
        if len(repo_features['func_names']) > 0:
            db_feature = mongoDB.mongodb_synic(host=config.db_host,
                                               port=config.db_port,
                                               db_feature=config.db_feature,
                                               collection_name=config.db_fn_collection)
            document = {}
            bf_fn = BloomFilter(max_elements=config.bloom_filter_volume, error_rate=config.bloom_filter_error_rate)
            [bf_fn.add(element) for element in repo_features['func_names']]
            bf_fn_pickle = cPickle.dumps(bf_fn)
            document[file.split('.json')[0]] = bf_fn_pickle
            db_feature.do_add(document_item=document)

        """build collection '1g'"""
        if len(repo_features['strings']) > 0:
            db_feature = mongoDB.mongodb_synic(host=config.db_host,
                                               port=config.db_port,
                                               db_feature=config.db_feature,
                                               collection_name=config.db_1g_collection)
            document = {}
            bf_1g = BloomFilter(max_elements=config.bloom_filter_volume, error_rate=config.bloom_filter_error_rate)
            [bf_1g.add(element) for element in repo_features['strings']]
            bf_1g_pickle = cPickle.dumps(bf_1g)
            document[file.split('.json')[0]] = bf_1g_pickle
            db_feature.do_add(document_item=document)

        """build collection '2g'"""
        if len(repo_features['strings']) > 0:
            db_feature = mongoDB.mongodb_synic(host=config.db_host,
                                               port=config.db_port,
                                               db_feature=config.db_feature,
                                               collection_name=config.db_2g_collection)
            document = {}
            bf_2g = BloomFilter(max_elements=config.bloom_filter_volume, error_rate=config.bloom_filter_error_rate)
            [bf_2g.add(" ".join(repo_features['strings'][index:index+1])) for index in range(len(repo_features['strings'])-1)]
            bf_2g_pickle = cPickle.dumps(bf_2g)
            document[file.split('.json')[0]] = bf_2g_pickle
            db_feature.do_add(document_item=document)

        """build collection '3g'"""
        if len(repo_features['strings']) > 0:
            db_feature = mongoDB.mongodb_synic(host=config.db_host,
                                               port=config.db_port,
                                               db_feature=config.db_feature,
                                               collection_name=config.db_3g_collection)
            bf_3g = BloomFilter(max_elements=config.bloom_filter_volume, error_rate=config.bloom_filter_error_rate)
            [bf_3g.add(" ".join(repo_features['strings'][index:index + 2])) for index in range(len(repo_features['strings']) - 2)]
            bf_3g_pickle = cPickle.dumps(bf_3g)
            document[file.split('.json')[0]] = bf_3g_pickle
            db_feature.do_add(document_item=document)

        """build collection 'string_arrays'"""
        if len(repo_features['string_arrays']) > 0:
            db_feature = mongoDB.mongodb_synic(host=config.db_host,
                                               port=config.db_port,
                                               db_feature=config.db_feature,
                                               collection_name=config.db_string_array_collection)
            document[file.split('.json')[0]] = repo_features['string_arrays']
            db_feature.do_add(document_item=document)

        """build collection 'const_num_arrays'"""
        if len(repo_features['const_num_arrays']) > 0:
            db_feature = mongoDB.mongodb_synic(host=config.db_host,
                                               port=config.db_port,
                                               db_feature=config.db_feature,
                                               collection_name=config.db_const_num_array_collection)
            document[file.split('.json')[0]] = repo_features['const_num_arrays']
            db_feature.do_add(document_item=document)

        """build collection 'const_enum_arrays'"""
        if len(repo_features['const_enum_arrays']) > 0:
            db_feature = mongoDB.mongodb_synic(host=config.db_host,
                                               port=config.db_port,
                                               db_feature=config.db_feature,
                                               collection_name=config.db_const_enum_array_collection)
            document[file.split('.json')[0]] = repo_features['const_enum_arrays']
            db_feature.do_add(document_item=document)
