
from pathlib import Path

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

import matplotlib.pyplot as plt


DATA_PATH = Path("data/phishing_site_urls.csv")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)

print("Loading dataset...")
df = pd.read_csv(DATA_PATH)

df = df.dropna(subset=["URL", "Label"]).copy()
df["URL"] = df["URL"].astype(str)
df["Label"] = df["Label"].astype(str).str.strip().str.lower()

# Explicit label mapping: bad = phishing, good = legitimate.
df = df[df["Label"].isin(["bad", "good"])]
df["target"] = df["Label"].map({"bad": 1, "good": 0})

# Remove exact URL duplicates to reduce redundant examples.

# Clean URL text and labels before checking duplicates.
df["URL"] = df["URL"].astype(str).str.strip()
df = df[df["URL"] != ""]

# Explicit label mapping: bad = phishing, good = legitimate.
df = df[df["Label"].isin(["bad", "good"])].copy()
df["target"] = df["Label"].map({"bad": 1, "good": 0})

# Remove every URL that has conflicting labels.
labels_per_url = df.groupby("URL")["Label"].nunique()
conflicting_urls = labels_per_url[labels_per_url > 1].index

print("Conflicting URLs removed:", len(conflicting_urls))
df = df[~df["URL"].isin(conflicting_urls)].copy()

# Remove repeated URLs after conflicts have been excluded.
before_deduplication = len(df)
df = df.drop_duplicates(subset=["URL"]).reset_index(drop=True)

print("Duplicate rows removed:", before_deduplication - len(df))
print("Unique URLs:", len(df))
print("\nClass distribution:")
print(df["Label"].value_counts())


print("Unique URLs:", len(df))
print("Class distribution:")
print(df["Label"].value_counts())

# Use a stratified sample to keep the first experiment manageable.
sample_size = min(100_000, len(df))

sample, _ = train_test_split(
    df,
    train_size=sample_size,
    stratify=df["target"],
    random_state=42,
)

X_train, X_test, y_train, y_test = train_test_split(
    sample["URL"],
    sample["target"],
    test_size=0.20,
    random_state=42,
    stratify=sample["target"],
)

# Character n-grams learn patterns from URL text.
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
            random_state=42,
        ),
    ),
])

print("\nTraining character-level TF-IDF model...")
model.fit(X_train, y_train)

predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)[:, 1]

print("\n=== TF-IDF + LOGISTIC REGRESSION ===")
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

# Save model and evaluation artifacts.
joblib.dump(model, MODEL_DIR / "tfidf_logistic_regression.joblib")

display = ConfusionMatrixDisplay(
    confusion_matrix=confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ),
    display_labels=["Legitimate", "Phishing"],
)
display.plot()
plt.title("TF-IDF + Logistic Regression — Confusion Matrix")
plt.tight_layout()
plt.savefig(MODEL_DIR / "tfidf_confusion_matrix.png")
plt.close()

comparison = pd.DataFrame({
    "URL": X_test.to_numpy(),
    "Actual_Label": y_test.map({0: "good", 1: "bad"}).to_numpy(),
    "Predicted_Label": pd.Series(predictions, index=y_test.index)
        .map({0: "good", 1: "bad"}).to_numpy(),
    "Phishing_Probability": probabilities,
})

comparison.to_csv(
    MODEL_DIR / "tfidf_test_predictions.csv",
    index=False,
)

print("\nSaved model: models/tfidf_logistic_regression.joblib")
print("Saved confusion matrix: models/tfidf_confusion_matrix.png")
print("Saved test predictions: models/tfidf_test_predictions.csv")
print("\nTraining complete!")
