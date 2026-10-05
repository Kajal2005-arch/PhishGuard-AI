
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)

DATA_PATH = Path("data/phishing_site_urls.csv")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)

print("Loading dataset...")
df = pd.read_csv(DATA_PATH)

# Clean URLs and labels
df = df.dropna(subset=["URL", "Label"]).copy()
df["URL"] = df["URL"].astype(str).str.strip()
df["Label"] = df["Label"].astype(str).str.strip().str.lower()

df = df[(df["URL"] != "") & df["Label"].isin(["bad", "good"])].copy()

# bad = phishing (1), good = legitimate (0)
df["target"] = df["Label"].map({"bad": 1, "good": 0})

# Remove URLs with conflicting labels before deduplication
label_counts = df.groupby("URL")["Label"].nunique()
conflicting_urls = label_counts[label_counts > 1].index
df = df[~df["URL"].isin(conflicting_urls)].copy()

# Keep one row per exact URL
df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)

# Extract hostname from URLs with or without a scheme
def get_hostname(url):
    try:
        value = url if "://" in url else "//" + url
        return (urlparse(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""

df["hostname"] = df["URL"].apply(get_hostname)

# URLs without a parseable hostname cannot be used in this evaluation
invalid_count = int((df["hostname"] == "").sum())
df = df[df["hostname"] != ""].copy()

print("Conflicting URLs excluded:", len(conflicting_urls))
print("Rows without a valid hostname excluded:", invalid_count)
print("Unique URLs with hostnames:", len(df))
print("\nOverall class distribution:")
print(df["Label"].value_counts())

# Keep the experiment manageable while preserving class balance.
# Group splitting below still prevents a hostname appearing in both sets.
sample_size = min(100_000, len(df))

sample, _ = __import__("sklearn.model_selection", fromlist=["train_test_split"]).train_test_split(
    df,
    train_size=sample_size,
    stratify=df["target"],
    random_state=42,
)

# Split by hostname, not by individual URL.
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(
        sample["URL"],
        sample["target"],
        groups=sample["hostname"],
    )
)

train = sample.iloc[train_idx]
test = sample.iloc[test_idx]

X_train = train["URL"]
y_train = train["target"]
X_test = test["URL"]
y_test = test["target"]

train_hosts = set(train["hostname"])
test_hosts = set(test["hostname"])
overlap = train_hosts.intersection(test_hosts)

print("\n=== HOSTNAME SPLIT ===")
print("Training URLs:", len(train))
print("Testing URLs:", len(test))
print("Training hostnames:", len(train_hosts))
print("Testing hostnames:", len(test_hosts))
print("Hostnames shared between sets:", len(overlap))
print("\nTest class distribution:")
print(test["target"].map({0: "good", 1: "bad"}).value_counts())

if len(overlap) != 0:
    raise RuntimeError("Hostname leakage detected!")

if y_train.nunique() < 2 or y_test.nunique() < 2:
    raise RuntimeError(
        "One split contains only one class. "
        "Try another random_state or split configuration."
    )

# Train a fresh model for this experiment.
# This does not overwrite the model used by your website.
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            max_features=100_000,
            min_df=2,
            sublinear_tf=True,
        ),
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        ),
    ),
])

print("\nTraining on training hostnames...")
model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\n=== UNSEEN-HOSTNAME EVALUATION ===")
print(f"Accuracy:  {accuracy_score(y_test, predictions):.4f}")
print(
    f"Precision: {precision_score(y_test, predictions, zero_division=0):.4f}"
)
print(
    f"Recall:    {recall_score(y_test, predictions, zero_division=0):.4f}"
)
print(f"F1 score:  {f1_score(y_test, predictions, zero_division=0):.4f}")

print("\nClassification report:")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Legitimate", "Phishing"],
    zero_division=0,
))

# Save under a separate name; do not replace the website model.
model_path = MODEL_DIR / "tfidf_unseen_domain_evaluation.joblib"
joblib.dump(model, model_path)

cm = confusion_matrix(y_test, predictions, labels=[0, 1])
display = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=["Legitimate", "Phishing"],
)
display.plot()
plt.title("Evaluation on Unseen Hostnames")
plt.tight_layout()
plt.savefig(MODEL_DIR / "unseen_domain_confusion_matrix.png")
plt.close()

print("\nSaved evaluation model:", model_path)
print("Saved confusion matrix: models/unseen_domain_confusion_matrix.png")
print("\nEvaluation complete!")
