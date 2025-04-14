import sys
import os
sys.path.append(os.path.abspath("../../model-training/scripts"))

from feature_extraction import FeatureExtractor

# In chatbot
def deep_analyze_url(url):
    features = FeatureExtractor.extract_comprehensive_features(url)
    # Need to use features with gradient boosting model