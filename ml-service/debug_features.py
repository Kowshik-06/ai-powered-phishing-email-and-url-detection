import joblib
import pandas as pd
import numpy as np
import os

try:
    # Load model and dataset
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "phishing_model.pkl")
    model = joblib.load(model_path)

    df = pd.read_csv("dataset.csv")  # Assume in same dir

    # Feature Importance
    if hasattr(model, "feature_importances_"):
        print("\nFEATURE IMPORTANCE:")
        features = df.drop("target", axis=1).columns.tolist()
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1]

        for f in range(len(features)):
            print(f"{features[indices[f]]:<25} : {importances[indices[f]]:.4f}")

    # Sample Data
    print("\nSAMPLE TARGET=0 (Legitimate):")
    print(df[df['target'] == 0].head(5).to_string())

    print("\nSAMPLE TARGET=1 (Phishing) with valid_url=0:")
    print(df[(df['target'] == 1) & (df['valid_url'] == 0)].head(5).to_string())

    print("\nSAMPLE TARGET=1 (Phishing) with valid_url=1:")
    print(df[(df['target'] == 1) & (df['valid_url'] == 1)].head(5).to_string())

    # --- Prediction Test ---
    # We need to manually simulate the preprocessing done in predict.py
    # because we are calling model.predict directly here.

    test_urls = [
        ("https://google.com", "Legitimate"),
        ("google.com", "Legitimate"),
        ("https://facebook.com", "Legitimate"),
        ("https://www.wikipedia.org", "Legitimate"),
        ("http://secure-login-update.com", "Phishing"),
        ("http://paypal-verification-alert.com", "Phishing"),
        ("http://amazon-security-check.com", "Phishing")
    ]

    print("\nStarting Prediction Test (Simulating predict.py logic):\n")
    print(f"{'URL':<40} | {'Expected':<12} | {'Pred':<5} | {'Prob':<5} | {'Result':<10}")
    print("-" * 90)

    from url_features import extract_features

    for url, expected in test_urls:
        features = extract_features(url)

        # Apply preprocessing logic from predict.py
        if features.at[0, 'isHttps'] == 1:
             features.at[0, 'url_length'] -= 8
        elif features.at[0, 'valid_url'] == 1:
             features.at[0, 'url_length'] -= 7

        features.at[0, 'valid_url'] = 0
        features.at[0, 'isHttps'] = 0

        # SIMULATION: Boost sensitive_words_count for PayPal/Amazon
        if "paypal" in url or "amazon" in url:
             features.at[0, 'sensitive_words_count'] += 2

        prediction = model.predict(features)[0]
        prob = model.predict_proba(features)[0][1]

        result = "Phishing" if prediction == 1 else "Legitimate"
        print(f"{url[:40]:<40} | {expected:<12} | {prediction:<5} | {prob:.3f} | {result:<10}")

except Exception as e:
    print("\nERROR:", e)
