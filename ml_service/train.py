import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder

from feature_extractor import extract_features, get_feature_columns

# ─────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "training_dataset.csv")
MODEL_PATH   = os.path.join(BASE_DIR, "saved_models", "threat_model.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "saved_models", "label_encoder.pkl")


# ─────────────────────────────────────────────
# Step 1: Load dataset
# ─────────────────────────────────────────────

def load_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    print(f"✅ Loaded dataset   : {len(df)} rows")
    print(f"   Label distribution:\n{df['label'].value_counts().to_string()}\n")
    return df


# ─────────────────────────────────────────────
# Step 2: Apply feature extractor to every row
# ─────────────────────────────────────────────

def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """
    Run extract_features() on every row of the dataset.
    This ensures train.py and api.py use IDENTICAL feature logic.
    """
    records = []
    for _, row in df.iterrows():
        raw_finding = {
            "payload":              row["payload"],
            "response_time":        row["response_time"],
            "status_code":          row["status_code"],
            "payload_reflected":    row["payload_reflected"],
            "error_detected":       row["error_detected"],
            "response_length_diff": row["response_length_diff"],
        }
        features = extract_features(raw_finding)
        records.append(features)

    feature_df = pd.DataFrame(records, columns=get_feature_columns())
    print(f"✅ Feature matrix   : {feature_df.shape[0]} rows x {feature_df.shape[1]} cols")
    return feature_df


# ─────────────────────────────────────────────
# Step 3: Train model
# ─────────────────────────────────────────────

def train_model(X_train, y_train) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=200,       # 200 trees — good accuracy without overfitting
        max_depth=15,           # prevent overfitting on small dataset
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced", # handles Clean class being larger
        random_state=42,
        n_jobs=-1               # use all CPU cores
    )
    model.fit(X_train, y_train)
    print("✅ Model trained")
    return model


# ─────────────────────────────────────────────
# Step 4: Evaluate
# ─────────────────────────────────────────────

def evaluate_model(model, X_test, y_test, encoder):
    y_pred = model.predict(X_test)

    print("\n" + "=" * 55)
    print("Classification Report")
    print("=" * 55)
    print(classification_report(
        y_test, y_pred,
        target_names=encoder.classes_
    ))

    print("Confusion Matrix")
    print("=" * 55)
    cm = confusion_matrix(y_test, y_pred)
    labels = encoder.classes_
    cm_df = pd.DataFrame(cm, index=labels, columns=labels)
    print(cm_df.to_string())

    # Feature importance
    print("\n" + "=" * 55)
    print("Top 10 Feature Importances")
    print("=" * 55)
    importances = pd.Series(
        model.feature_importances_,
        index=get_feature_columns()
    ).sort_values(ascending=False)
    print(importances.head(10).to_string())


# ─────────────────────────────────────────────
# Step 5: Save model + encoder
# ─────────────────────────────────────────────

def save_artifacts(model, encoder):
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model,   MODEL_PATH)
    joblib.dump(encoder, ENCODER_PATH)
    print(f"\n✅ Model saved      : {MODEL_PATH}")
    print(f"✅ Encoder saved    : {ENCODER_PATH}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print("=" * 55)
    print("ML Service — Training Pipeline")
    print("=" * 55 + "\n")

    # Load
    df = load_dataset(DATASET_PATH)

    # Features
    X = build_feature_matrix(df)

    # Encode labels  (Clean=0, CSRF=1, Open Redirect=2, SQLi=3, XSS=4)
    encoder = LabelEncoder()
    y = encoder.fit_transform(df["label"])
    print(f"✅ Labels encoded   : {dict(enumerate(encoder.classes_))}\n")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"✅ Train size        : {len(X_train)}")
    print(f"   Test size         : {len(X_test)}\n")

    # Train
    model = train_model(X_train, y_train)

    # Evaluate
    evaluate_model(model, X_test, y_test, encoder)

    # Save
    save_artifacts(model, encoder)

    print("\n🎉 Training complete. Ready for api.py")


if __name__ == "__main__":
    main()