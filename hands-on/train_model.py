"""Training utilities for the phishing detector and threat actor profiler."""

import json
import os

import numpy as np
import pandas as pd
from pycaret.classification import (
    compare_models,
    finalize_model,
    plot_model,
    save_model,
    setup,
)
from pycaret.clustering import (
    create_model as create_cluster_model,
    save_model as save_cluster_model,
    setup as clustering_setup,
)


def generate_synthetic_data(num_samples: int = 500) -> pd.DataFrame:
    """Generate synthetic phishing/benign data with actor profile signals."""
    print("Generating synthetic dataset...")

    features = [
        "having_IP_Address",
        "URL_Length",
        "Shortining_Service",
        "having_At_Symbol",
        "double_slash_redirecting",
        "Prefix_Suffix",
        "having_Sub_Domain",
        "SSLfinal_State",
        "URL_of_Anchor",
        "Links_in_tags",
        "SFH",
        "Abnormal_URL",
        "has_political_keyword",
    ]

    num_phishing = num_samples // 2
    num_benign = num_samples - num_phishing

    # Divide malicious samples among three actor profiles
    num_state = num_phishing // 3
    num_org = num_phishing // 3
    num_hacktivist = num_phishing - num_state - num_org

    state_sponsored = {
        "having_IP_Address": np.random.choice([1, -1], num_state, p=[0.1, 0.9]),
        "URL_Length": np.random.choice([1, 0, -1], num_state, p=[0.4, 0.5, 0.1]),
        "Shortining_Service": np.random.choice([1, -1], num_state, p=[0.1, 0.9]),
        "having_At_Symbol": np.random.choice([1, -1], num_state, p=[0.3, 0.7]),
        "double_slash_redirecting": np.random.choice([1, -1], num_state, p=[0.2, 0.8]),
        "Prefix_Suffix": np.random.choice([1, -1], num_state, p=[0.8, 0.2]),
        "having_Sub_Domain": np.random.choice([1, 0, -1], num_state, p=[0.5, 0.3, 0.2]),
        "SSLfinal_State": np.random.choice([-1, 0, 1], num_state, p=[0.1, 0.1, 0.8]),
        "URL_of_Anchor": np.random.choice([-1, 0, 1], num_state, p=[0.2, 0.3, 0.5]),
        "Links_in_tags": np.random.choice([-1, 0, 1], num_state, p=[0.2, 0.3, 0.5]),
        "SFH": np.random.choice([-1, 0, 1], num_state, p=[0.6, 0.2, 0.2]),
        "Abnormal_URL": np.random.choice([1, -1], num_state, p=[0.3, 0.7]),
        "has_political_keyword": np.random.choice([1, 0], num_state, p=[0.1, 0.9]),
    }

    organized_crime = {
        "having_IP_Address": np.random.choice([1, -1], num_org, p=[0.8, 0.2]),
        "URL_Length": np.random.choice([1, 0, -1], num_org, p=[0.6, 0.3, 0.1]),
        "Shortining_Service": np.random.choice([1, -1], num_org, p=[0.7, 0.3]),
        "having_At_Symbol": np.random.choice([1, -1], num_org, p=[0.5, 0.5]),
        "double_slash_redirecting": np.random.choice([1, -1], num_org, p=[0.4, 0.6]),
        "Prefix_Suffix": np.random.choice([1, -1], num_org, p=[0.5, 0.5]),
        "having_Sub_Domain": np.random.choice([1, 0, -1], num_org, p=[0.7, 0.2, 0.1]),
        "SSLfinal_State": np.random.choice([-1, 0, 1], num_org, p=[0.7, 0.2, 0.1]),
        "URL_of_Anchor": np.random.choice([-1, 0, 1], num_org, p=[0.6, 0.2, 0.2]),
        "Links_in_tags": np.random.choice([-1, 0, 1], num_org, p=[0.6, 0.2, 0.2]),
        "SFH": np.random.choice([-1, 0, 1], num_org, p=[0.6, 0.2, 0.2]),
        "Abnormal_URL": np.random.choice([1, -1], num_org, p=[0.9, 0.1]),
        "has_political_keyword": np.random.choice([1, 0], num_org, p=[0.05, 0.95]),
    }

    hacktivist = {
        "having_IP_Address": np.random.choice([1, -1], num_hacktivist, p=[0.4, 0.6]),
        "URL_Length": np.random.choice([1, 0, -1], num_hacktivist, p=[0.5, 0.3, 0.2]),
        "Shortining_Service": np.random.choice([1, -1], num_hacktivist, p=[0.4, 0.6]),
        "having_At_Symbol": np.random.choice([1, -1], num_hacktivist, p=[0.4, 0.6]),
        "double_slash_redirecting": np.random.choice([1, -1], num_hacktivist, p=[0.3, 0.7]),
        "Prefix_Suffix": np.random.choice([1, -1], num_hacktivist, p=[0.6, 0.4]),
        "having_Sub_Domain": np.random.choice([1, 0, -1], num_hacktivist, p=[0.4, 0.4, 0.2]),
        "SSLfinal_State": np.random.choice([-1, 0, 1], num_hacktivist, p=[0.3, 0.3, 0.4]),
        "URL_of_Anchor": np.random.choice([-1, 0, 1], num_hacktivist, p=[0.4, 0.3, 0.3]),
        "Links_in_tags": np.random.choice([-1, 0, 1], num_hacktivist, p=[0.4, 0.3, 0.3]),
        "SFH": np.random.choice([-1, 0, 1], num_hacktivist, p=[0.4, 0.3, 0.3]),
        "Abnormal_URL": np.random.choice([1, -1], num_hacktivist, p=[0.6, 0.4]),
        "has_political_keyword": np.random.choice([1, 0], num_hacktivist, p=[0.7, 0.3]),
    }

    df_phishing = pd.concat(
        [
            pd.DataFrame(state_sponsored),
            pd.DataFrame(organized_crime),
            pd.DataFrame(hacktivist),
        ],
        ignore_index=True,
    )

    benign_data = {
        "having_IP_Address": np.random.choice([1, -1], num_benign, p=[0.05, 0.95]),
        "URL_Length": np.random.choice([1, 0, -1], num_benign, p=[0.1, 0.6, 0.3]),
        "Shortining_Service": np.random.choice([1, -1], num_benign, p=[0.1, 0.9]),
        "having_At_Symbol": np.random.choice([1, -1], num_benign, p=[0.05, 0.95]),
        "double_slash_redirecting": np.random.choice([1, -1], num_benign, p=[0.05, 0.95]),
        "Prefix_Suffix": np.random.choice([1, -1], num_benign, p=[0.1, 0.9]),
        "having_Sub_Domain": np.random.choice([1, 0, -1], num_benign, p=[0.1, 0.4, 0.5]),
        "SSLfinal_State": np.random.choice([-1, 0, 1], num_benign, p=[0.05, 0.15, 0.8]),
        "URL_of_Anchor": np.random.choice([-1, 0, 1], num_benign, p=[0.1, 0.2, 0.7]),
        "Links_in_tags": np.random.choice([-1, 0, 1], num_benign, p=[0.1, 0.2, 0.7]),
        "SFH": np.random.choice([-1, 0, 1], num_benign, p=[0.1, 0.1, 0.8]),
        "Abnormal_URL": np.random.choice([1, -1], num_benign, p=[0.1, 0.9]),
        "has_political_keyword": np.zeros(num_benign),
    }

    df_benign = pd.DataFrame(benign_data)

    df_phishing["label"] = 1
    df_benign["label"] = 0

    final_df = pd.concat([df_phishing, df_benign], ignore_index=True)
    return final_df.sample(frac=1, random_state=42).reset_index(drop=True)


def train():
    model_path = 'models/phishing_url_detector'
    plot_path = 'models/feature_importance.png'

    if os.path.exists(model_path + '.pkl'):
        print("Model and plot already exist. Skipping training.")
        return

    data = generate_synthetic_data()
    os.makedirs('data', exist_ok=True)
    data.to_csv('data/phishing_synthetic.csv', index=False)

    print("Initializing PyCaret Setup...")
    s = setup(data, target='label', session_id=42, verbose=False)

    print("Comparing models...")
    best_model = compare_models(n_select=1, include=['rf', 'et', 'lightgbm'])

    print("Finalizing model...")
    final_model = finalize_model(best_model)

    # NEW: Plot feature importance and save it to a file
    print("Saving feature importance plot...")
    os.makedirs('models', exist_ok=True)
    plot_model(final_model, plot='feature', save=True)
    # PyCaret saves it as 'Feature Importance.png', let's rename it
    os.rename('Feature Importance.png', plot_path)

    print("Saving model...")
    save_model(final_model, model_path)
    print("Classification model saved.")

    # --- Train clustering model for attribution ---
    print("Setting up clustering workflow...")
    clustering_data = data.drop("label", axis=1)
    clustering_setup(clustering_data, session_id=42, verbose=False)
    cluster_model = create_cluster_model("kmeans", num_clusters=3)

    print("Saving clustering model...")
    save_cluster_model(cluster_model, "models/threat_actor_profiler")

    centers = pd.DataFrame(cluster_model.cluster_centers_, columns=clustering_data.columns)
    mapping = {}
    for idx, center in centers.iterrows():
        if center["has_political_keyword"] > 0.5:
            profile = "Hacktivist"
        elif center["having_IP_Address"] > 0.5 and center["Shortining_Service"] > 0.5:
            profile = "Organized Cybercrime"
        else:
            profile = "State-Sponsored"
        mapping[idx] = profile

    with open("models/cluster_mapping.json", "w") as f:
        json.dump(mapping, f)

    print("Clustering model and mapping saved successfully.")


if __name__ == "__main__":
    train()