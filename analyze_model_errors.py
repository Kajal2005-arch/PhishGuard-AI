
import pandas as pd
from pathlib import Path
from urllib.parse import urlparse
import joblib
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import confusion_matrix

DATA_PATH = Path("data/phishing_site_urls.csv")
MODEL_PATH = Path("models/tfidf_unseen_domain_evaluation.joblib")

df = pd.read_csv(DATA_PATH)
df = df.dropna(subset=["URL", "Label"]).copy()
df["URL"] = df["URL"].astype(str).str.strip()
df["Label"] = df["Label"].astype(str).str.strip().str.lower()
df = df[(df["URL"] != "") & df["Label"].isin(["bad", "good"])].copy()
df["target"] = df["Label"].map({"bad": 1, "good": 0})

# Remove URLs with conflicting labels.
conflicts = df.groupby("URL")["Label"].nunique()
conflicting_urls = conflicts[conflicts > 1].index
df = df[~df["URL"].isin(conflicting_urls)].copy()
df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)

def get_hostname(url):
    try:
        value = url if "://" in url else "//" + url
        return (urlparse(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""

df["hostname"] = df["URL"].apply(get_hostname)
df = df[df["hostname"] != ""].copy()

# Reproduce the same sampling and hostname split.
from sklearn.model_selection import train_test_split

sample, _ = train_test_split(
    df,
    train_size=min(100_000, len(df)),
    stratify=df["target"],
    random_state=42,
)

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

_, test_idx = next(
    splitter.split(
        sample["URL"],
        sample["target"],
        groups=sample["hostname"],
    )
)

test = sample.iloc[test_idx].copy()

# Load the already-trained evaluation model.
model = joblib.load(MODEL_PATH)

test["predicted"] = model.predict(test["URL"])
test["phishing_score"] = model.predict_proba(test["URL"])[:, 1]

# Confusion matrix order: legitimate (0), phishing (1)
print("Confusion matrix:")
print(confusion_matrix(test["target"], test["predicted"], labels=[0, 1]))

# False positives: actual legitimate, predicted phishing.
false_positives = test[
    (test["target"] == 0) & (test["predicted"] == 1)
].sort_values("phishing_score", ascending=False)

# False negatives: actual phishing, predicted legitimate.
false_negatives = test[
    (test["target"] == 1) & (test["predicted"] == 0)
].sort_values("phishing_score", ascending=True)

print("\n=== FALSE POSITIVES (LEGITIMATE LABELED URLS FLAGGED) ===")
print("Count:", len(false_positives))
print(
    false_positives[
        ["URL", "hostname", "phishing_score"]
    ].head(15).to_string(index=False)
)

print("\n=== FALSE NEGATIVES (PHISHING LABELED URLS MISSED) ===")
print("Count:", len(false_negatives))
print(
    false_negatives[
        ["URL", "hostname", "phishing_score"]
    ].head(15).to_string(index=False)
)

# Save mistakes for later analysis.
errors = pd.concat([
    false_positives.assign(error_type="false_positive"),
    false_negatives.assign(error_type="false_negative"),
])

errors.to_csv("models/unseen_domain_errors.csv", index=False)
print("\nSaved all errors to models/unseen_domain_errors.csv")
