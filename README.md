requirement

python3
clang
pymongodb


#####
collection test data
program entry
#####
B2SFinder/Test_Data_Collection/collection_data_to_DB.py


#####
extract features from source code
program entry
#####
B2SFinder/SourceFeatureExtract/extract_source_feature.py
features are generated and saved in json files to local path ./output

#####
save extracted features into AWS DB
program entry
#####
B2SFinder/Generate_Feature_to_DB/save_feature_DB.py

#####
predicted and test binary_engine
program entry
#####
B2SFinder/Binary_Engine/bt_predictor.py