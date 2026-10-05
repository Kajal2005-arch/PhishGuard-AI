
from pathlib import Path
from audit_log import append_audit_event

import joblib
import pandas as pd
from flask import Flask, render_template, request
from urllib.parse import urlsplit

from crypto_utils import url_fingerprint
from verified_threat_store import load_verified_records
from feature_extraction import extract_features

app = Flask(__name__)

MODEL_PATH = Path("models/random_forest.joblib")

saved = joblib.load(MODEL_PATH)
model = saved["model"]
feature_names = saved["feature_names"]


def explain_features(url, features):
    reasons = []

    if features["url_length"] > 75:
        reasons.append("The URL is unusually long.")

    if features["ip_address_present"]:
        reasons.append("The hostname appears to use an IP address.")

    if features["at_count"]:
        reasons.append("The URL contains an @ symbol.")

    if features["subdomain_count"] >= 3:
        reasons.append("The hostname contains several subdomain levels.")

    if features["suspicious_word_count"] >= 2:
        reasons.append(
            "The URL contains multiple terms often associated "
            "with account or security actions."
        )

    if features["hyphen_count"] >= 3:
        reasons.append("The URL contains several hyphens.")

    if not reasons:
        reasons.append(
            "No URL patterns from our basic explanation rules "
            "were triggered. This does not guarantee safety."
        )

    return reasons


def validate_url(value):
    value = value.strip()

    if not value:
        return None, "Please enter a URL."

    if len(value) > 2048:
        return None, "Please enter a URL shorter than 2048 characters."

    # Allow users to enter example.com without a scheme.
    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname

        if (
            parsed.scheme not in ("http", "https")
            or not hostname
            or "." not in hostname
            or any(char.isspace() for char in value)
        ):
            return None, "Please enter a valid HTTP or HTTPS URL."

        # Accessing port can raise ValueError for malformed ports.
        _ = parsed.port

    except ValueError:
        return None, "Please enter a valid URL."

    return value, None


def find_verified_report(url):
    """Find signed registry reports matching a URL fingerprint."""
    fingerprint = url_fingerprint(url)

    public_key_path = Path("keys/ed25519_public.pem")
    registry_path = Path("data/threat_registry.json")

    result = {
        "fingerprint": fingerprint,
        "status": "not_found",
        "reports": [],
    }

    if not public_key_path.exists():
        result["status"] = "unavailable"
        return result

    try:
        verified_records = load_verified_records(
            public_key_path,
            registry_path,
        )

        for item in verified_records:
            record = item["record"]

            if record["url_fingerprint"] == fingerprint:
                result["reports"].append({
                    "status": record["status"],
                    "source": record["source"],
                })

        if result["reports"]:
            result["status"] = "verified_report_found"

    except Exception:
        app.logger.exception("Threat registry verification failed.")
        result["status"] = "unavailable"

    return result


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    submitted_url = ""

    if request.method == "POST":
        submitted_url = request.form.get("url", "")
        url, error = validate_url(submitted_url)

        if url:
            try:
                features = extract_features([url])
                features = features.reindex(
                    columns=feature_names, fill_value=0
                )

                prediction = int(model.predict(features)[0])

                probability = None
                if hasattr(model, "predict_proba"):
                    probability = float(
                        model.predict_proba(features)[0][1]
                    )

                result = {
                    "threat_registry": find_verified_report(url),
                    "label": (
                        "Potential phishing"
                        if prediction == 1
                        else "Likely legitimate"
                    ),
                    "is_phishing": prediction == 1,
                    "probability": (
                        round(probability * 100, 1)
                        if probability is not None
                        else None
                    ),
                    "reasons": explain_features(
                        url, features.iloc[0]
                    ),
                }

                # Record the completed scan in the audit log.
                # Store the fingerprint instead of the raw URL.
                try:
                    append_audit_event(
                        "scan_completed",
                        {
                            "url_fingerprint": (
                                result["threat_registry"]["fingerprint"]
                            ),
                            "prediction": result["label"],
                            "registry_status": (
                                result["threat_registry"]["status"]
                            ),
                        },
                    )
                except Exception:
                    app.logger.exception(
                        "Audit event could not be recorded."
                    )

            except Exception:
                app.logger.exception("URL prediction failed.")
                error = "The scan failed. Please check the server log."

    return render_template(
        "index.html",
        result=result,
        error=error,
        submitted_url=submitted_url,
    )


if __name__ == "__main__":
    app.run(debug=True)
