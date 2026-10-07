import re
import pandas as pd

def extract_features(url):
    features = {}

    features['url_length'] = len(url)
    features['valid_url'] = 1 if url.startswith("http") else 0
    features['at_symbol'] = 1 if "@" in url else 0
    features['sensitive_words_count'] = sum(word in url.lower() for word in ["login","secure","bank","verify","update"])
    features['path_length'] = len(url.split("/")) - 3 if "/" in url else 0
    features['isHttps'] = 1 if url.startswith("https") else 0
    features['nb_dots'] = url.count(".")
    features['nb_hyphens'] = url.count("-")
    features['nb_and'] = url.count("&")
    features['nb_or'] = url.lower().count("or")
    features['nb_www'] = url.lower().count("www")
    features['nb_com'] = url.lower().count("com")
    features['nb_underscore'] = url.count("_")

    return pd.DataFrame([features])
