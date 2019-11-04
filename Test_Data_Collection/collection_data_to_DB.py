######
###### Downloads test dataset and save them into mongodb
######

###### dataset format: {library_name:{source_code:{version_1: source_code_url, version_2: source_code_url, ...},
######                                binary_code:{version_1: library_code_url, version_2, library_code_url, ...}}}

###### DB: mongodb
######

###################################################test data
import json
import os
import bs4
import requests
import sys
sys.path.append('/home/wufeng/B2S/B2SFinder/DB')
sys.path.append('/home/wufeng/B2S/B2SFinder/Generate_Feature_to_DB')
import mongoDB
import config


def save_dataset_mongoDB(db_name, url_path, dataset_length):
    document_item = {}
    with open(url_path, encoding='utf-8', errors='ignore') as json_data:
        lines = json_data.readlines()
        count = 0
        for line in lines:
            line_dict = json.loads(line)
            library_name = line_dict.get('Library')
            document_url = line_dict.get('Link')
            if library_name in document_item.keys() and document_item.get(library_name) is not None:
                continue
            if count >= dataset_length:
                break
            library_dict = {}
            try:
                xml = requests.get(url=document_url)
                if xml.status_code == 200:
                    content = xml.content.decode('utf-8')
                    soup = bs4.BeautifulSoup(content, "html.parser")
                    content_potential = soup.find_all('a')
                    binary_dict = {}
                    source_dict = {}
                    for index in content_potential:
                        href_content = index.attrs.get("href")
                        if str(href_content).endswith(".deb") is True:
                            binary_dict["_".join(href_content.split('.deb')[0].split('_')[-2:])] = os.path.join(
                                document_url, href_content)
                        if str(href_content).endswith(".gz") is True:
                            source_dict[href_content.split('.orig.tar.gz')[0].split('_')[1]] = os.path.join(
                                document_url, href_content)
                        else:
                            continue
                    if len(binary_dict) >= 1 and len(source_dict) >= 1:
                        library_dict['source_code'] = source_dict
                        library_dict['binary_code'] = binary_dict
                        document_item[library_name] = library_dict
                        count += 1
                        print("collection test data; count: %d/%d" % (count, dataset_length))
                        print("add data into DB:...")
                        db_name.do_add({library_name: library_dict})
                        print("finished!...")
            except Exception as e:
                continue


if __name__ == '__main__':
    collection_name = "test_data"
    db_name_test_data = 'Binary_Engine_Test_Data'
    db_name = mongoDB.mongodb_synic(host=config.db_host,
                                    port=config.db_port,
                                    db_name=db_name_test_data,
                                    collection_name=collection_name)
    document_path = '/home/wufeng/B2S/B2SFinder/Test_Data_Collection/binary_data.json'
    save_dataset_mongoDB(db_name, document_path, config.test_data_length)
