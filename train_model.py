
from pathlib import Path
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
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

import matplotlib.pyplot as plt

from feature_extraction import extract_features


DATA_PATH = Path("data/phishing_site_urls.csv")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)

print("Loading dataset...")
df = pd.read_csv(DATA_PATH)

df = df.dropna(subset=["URL", "Label"])
df["URL"] = df["URL"].astype(str)
df["Label"] = df["Label"].astype(str).str.strip().str.lower()

# Explicit mapping: 1 = bad/phishing, 0 = good/legitimate
label_map = {"bad": 1, "good": 0}
df = df[df["Label"].isin(label_map)]

# Remove exact duplicate URL-label pairs.
df = df.drop_duplicates(subset=["URL", "Label"])

# Prevent identical URLs from appearing in both train and test.
# If the same URL has conflicting labels, exclude it.
conflicts = df.groupby("URL")["Label"].nunique()
conflicting_urls = conflicts[conflicts > 1].index
df = df[~df["URL"].isin(conflicting_urls)]

# Stratified sample for an initial, manageable experiment.
# Increase SAMPLE_SIZE after the pipeline works.
SAMPLE_SIZE = min(150_000, len(df))

df = df.groupby("Label", group_keys=False).apply(
    lambda group: group.sample(
        n=max(
            1,
            round(SAMPLE_SIZE * len(group) / len(df))
        ),
        random_state=42
    )
).reset_index(drop=True)

X = extract_features(df["URL"])
y = df["Label"].map(label_map).astype(int)

print("\nDataset size:", len(df))
print("Feature count:", X.shape[1])
print("Label counts:")
print(y.value_counts())

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

models = {
    "Random Forest": RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    ),
    "Decision Tree": DecisionTreeClassifier(
        max_depth=20,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
    ),
    "Logistic Regression": make_pipeline(
        SimpleImputer(strategy="median"),
        StandardScaler(),
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        ),
    ),
}

results = []

for name, model in models.items():
    print(f"\nTraining {name}...")

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    metrics = {
        "Model": name,
        "Accuracy": accuracy_score(y_test, predictions),
        "Precision": precision_score(
            y_test, predictions, zero_division=0
        ),
        "Recall": recall_score(
            y_test, predictions, zero_division=0
        ),
        "F1 Score": f1_score(
            y_test, predictions, zero_division=0
        ),
    }
    results.append(metrics)

    print(pd.Series(metrics).to_string())
    print("\nClassification report:")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    ))

    # Save the trained model and feature order.
    joblib.dump(
        {
            "model": model,
            "feature_names": X.columns.tolist(),
            "label_map": label_map,
        },
        MODEL_DIR / f"{name.lower().replace(' ', '_')}.joblib",
    )

    # Save confusion matrix.
    display = ConfusionMatrixDisplay(
        confusion_matrix=confusion_matrix(
            y_test, predictions, labels=[0, 1]
        ),
        display_labels=["Legitimate", "Phishing"],
    )
    display.plot()
    plt.title(f"{name} — Confusion Matrix")
    plt.tight_layout()
    plt.savefig(
        MODEL_DIR / f"{name.lower().replace(' ', '_')}_confusion.png"
    )
    plt.close()

results_df = pd.DataFrame(results)
results_df.to_csv(MODEL_DIR / "model_comparison.csv", index=False)

print("\n=== MODEL COMPARISON ===")
print(results_df.to_string(index=False))

print("\nTraining complete! Check the models folder.")
