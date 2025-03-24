import sys
import os
sys.path.append(os.path.abspath("../../model-training/scripts"))

from feature_extraction import FeatureExtractor

# In browser extension backend
def analyze_url(url):
    features = FeatureExtractor.extract_lightweight_features(url)
    # Need to use features with random forest model