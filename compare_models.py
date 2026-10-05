
import os
import pandas as pd
import tldextract

from sklearn.model_selection import GroupShuffleSplit
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from feature_extraction import extract_features

DATA_PATH = "data/phishing_site_urls.csv"
OUTPUT_PATH = "models/model_comparison.csv"
RANDOM_STATE = 42
SAMPLE_SIZE = 100_000

# 1. Load and clean the dataset
print("Loading dataset...")
df = pd.read_csv(DATA_PATH)

df["URL"] = df["URL"].astype(str).str.strip()
df["Label"] = df["Label"].astype(str).str.strip().str.lower()

df = df[df["Label"].isin(["good", "bad"])].copy()
df = df[df["URL"].ne("")].copy()
df["target"] = df["Label"].map({"good": 0, "bad": 1})

# Remove URLs that have conflicting labels
conflicts = df.groupby("URL")["target"].nunique()
conflicting_urls = conflicts[conflicts > 1].index
df = df[~df["URL"].isin(conflicting_urls)].copy()
df = df.drop_duplicates(subset="URL").copy()

# 2. Extract registered domains for a leakage-resistant split
extractor = tldextract.TLDExtract(suffix_list_urls=None)

def get_registered_domain(url):
    parsed = extractor(str(url).strip())
    if not parsed.domain or not parsed.suffix:
        return None
    return f"{parsed.domain}.{parsed.suffix}".lower()

df["registered_domain"] = df["URL"].apply(get_registered_domain)
df = df.dropna(subset=["registered_domain"]).copy()

# 3. Use the same stratified sample and split for both models
if len(df) > SAMPLE_SIZE:
    df = (
        df.groupby("target", group_keys=False)
        .sample(frac=SAMPLE_SIZE / len(df), random_state=RANDOM_STATE)
        .copy()
    )

df = df.reset_index(drop=True)

X = df["URL"]
y = df["target"]
groups = df["registered_domain"]

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=RANDOM_STATE,
)

train_idx, test_idx = next(splitter.split(X, y, groups=groups))

X_train = X.iloc[train_idx].tolist()
X_test = X.iloc[test_idx].tolist()
y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

train_domains = set(groups.iloc[train_idx])
test_domains = set(groups.iloc[test_idx])

print(f"\nTraining URLs: {len(X_train):,}")
print(f"Testing URLs: {len(X_test):,}")
print(f"Shared registered domains: {len(train_domains & test_domains)}")

if train_domains & test_domains:
    raise RuntimeError("Domain leakage detected!")

# 4. Train the Random Forest using engineered features
print("\nTraining Random Forest...")
rf_train_features = extract_features(X_train)
rf_test_features = extract_features(X_test)

rf_model = RandomForestClassifier(
    n_estimators=100,
    random_state=RANDOM_STATE,
    class_weight="balanced",
    n_jobs=-1,
)

rf_model.fit(rf_train_features, y_train)
rf_predictions = rf_model.predict(rf_test_features)

# 5. Train TF-IDF + Logistic Regression on the same URLs
print("\nTraining TF-IDF + Logistic Regression...")

tfidf_model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            max_features=100_000,
            min_df=2,
            sublinear_tf=True,
            dtype="float32",
        ),
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=RANDOM_STATE,
        ),
    ),
])

tfidf_model.fit(X_train, y_train)
tfidf_predictions = tfidf_model.predict(X_test)

# 6. Calculate comparable metrics
def evaluate_model(name, predictions):
    return {
        "Model": name,
        "Accuracy": accuracy_score(y_test, predictions),
        "Precision": precision_score(
            y_test, predictions, zero_division=0
        ),
        "Recall": recall_score(
            y_test, predictions, zero_division=0
        ),
        "F1-score": f1_score(
            y_test, predictions, zero_division=0
        ),
        "False Positives": int(
            ((y_test == 0) & (predictions == 1)).sum()
        ),
        "False Negatives": int(
            ((y_test == 1) & (predictions == 0)).sum()
        ),
    }

results = pd.DataFrame([
    evaluate_model("Random Forest", rf_predictions),
    evaluate_model("TF-IDF + Logistic Regression", tfidf_predictions),
])

print("\n=== MODEL COMPARISON ===")
print(results.round(4).to_string(index=False))

print("\n=== RANDOM FOREST CONFUSION MATRIX ===")
print(confusion_matrix(y_test, rf_predictions, labels=[0, 1]))

print("\n=== TF-IDF CONFUSION MATRIX ===")
print(confusion_matrix(y_test, tfidf_predictions, labels=[0, 1]))

# 7. Save the comparison results
os.makedirs("models", exist_ok=True)
results.to_csv(OUTPUT_PATH, index=False)

print(f"\nComparison saved to: {OUTPUT_PATH}")
print("Both models were evaluated on the same test URLs.")
