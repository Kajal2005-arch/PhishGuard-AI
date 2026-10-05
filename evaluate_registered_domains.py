
import pandas as pd
import tldextract

from sklearn.model_selection import GroupShuffleSplit
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.pipeline import Pipeline

DATA_PATH = "data/phishing_site_urls.csv"
RANDOM_STATE = 42
SAMPLE_SIZE = 100_000

print("Loading dataset...")
df = pd.read_csv(DATA_PATH)

df["URL"] = df["URL"].astype(str).str.strip()
df["Label"] = df["Label"].astype(str).str.strip().str.lower()

df = df[df["Label"].isin(["good", "bad"])].copy()
df = df[df["URL"].ne("")].copy()

# Convert labels: good = 0, bad = 1
df["target"] = df["Label"].map({"good": 0, "bad": 1})

# Remove every URL that has conflicting labels.
conflicts = df.groupby("URL")["target"].nunique()
conflicting_urls = conflicts[conflicts > 1].index
df = df[~df["URL"].isin(conflicting_urls)].copy()

# Remove duplicate URL records.
df = df.drop_duplicates(subset="URL").copy()

# Extract registered domains without making network requests.
extractor = tldextract.TLDExtract(suffix_list_urls=None)

def registered_domain(url):
    url = str(url).strip()
    parsed = extractor(url)

    if not parsed.domain or not parsed.suffix:
        return None

    return f"{parsed.domain}.{parsed.suffix}".lower()

df["registered_domain"] = df["URL"].apply(registered_domain)
df = df.dropna(subset=["registered_domain"]).copy()

print(f"Clean URLs: {len(df):,}")
print(f"Unique registered domains: {df['registered_domain'].nunique():,}")
print("\nClass distribution:")
print(df["target"].map({0: "good", 1: "bad"}).value_counts())

# Sample URLs while preserving the class proportions.
if len(df) > SAMPLE_SIZE:
    df = (
        df.groupby("target", group_keys=False)
        .sample(
            n=None,
            frac=SAMPLE_SIZE / len(df),
            random_state=RANDOM_STATE,
        )
        .copy()
    )

X = df["URL"]
y = df["target"]
groups = df["registered_domain"]

# Split by registered domain so no registered domain appears in both sets.
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=RANDOM_STATE,
)

train_idx, test_idx = next(splitter.split(X, y, groups=groups))

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
train_domains = set(groups.iloc[train_idx])
test_domains = set(groups.iloc[test_idx])

print(f"\nTraining URLs: {len(X_train):,}")
print(f"Testing URLs: {len(X_test):,}")
print(f"Shared registered domains: {len(train_domains & test_domains)}")

model = Pipeline([
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

print("\nTraining model...")
model.fit(X_train, y_train)

print("Evaluating...")
predictions = model.predict(X_test)

print(f"\nAccuracy:  {accuracy_score(y_test, predictions):.4f}")
print(f"Precision: {precision_score(y_test, predictions, zero_division=0):.4f}")
print(f"Recall:    {recall_score(y_test, predictions, zero_division=0):.4f}")
print(f"F1-score:  {f1_score(y_test, predictions, zero_division=0):.4f}")

print("\nConfusion matrix [good, bad]:")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

print("\nClassification report:")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    )
)

print("\nRegistered-domain evaluation complete.")
