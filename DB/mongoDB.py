import pymongo


class mongodb_synic():

    def __init__(self, host, port, db_name, collection_name):
        """
        :param host: ip
        :param username:
        :param password:
        :param port:
        :param authSource:'admin'
        :param db_name:
        :param collection_name:
        """
        self.host = host
        self.port = port
        self.db_name = db_name
        self.collection_name = collection_name
        self.client = pymongo.MongoClient(self.host, port=self.port)
        self.db = self.client[self.db_name]
        self.collection = self.db[self.collection_name]


    def do_drop(self):
        """
        # empty a collections of db
        :return:
        """
        self.collection.drop()

    def do_add(self, document_item):
        """
        :param string_lists: eg. {lib1_fn: string_list, lib1_1g: string_list, lib1_2g: string_list, ..., }
        :return:
        """
        try:
            self.collection.insert(document_item,  check_keys=False)
        except Exception as e:
            print(e)

    def do_query(self):
        """
        :param string_features: [str1, str2, str3, str4, ..., ]
        :return: {lib1_fn: count1, lib1_1g: count2, lib1_2g: count3, ..., }
        """
        return self.collection
        # result = []
        # for document in cursor:
        #     document.pop('_id')
        #     result.append(list(document.items())[0])
        # return result

    def do_count(self, type):
        """
        # count the number of documents in mongoDB
        :return:
        """
        return self.collection.count_documents()

    def do_replace(self, id, document):
        """
        # replace the content of OBjectID in mongoDB
        :param id:
        :param document:
        :return:
        """
        self.collection.replace_one({'_id': id}, document)
