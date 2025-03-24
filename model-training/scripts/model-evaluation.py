import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import json
import os
from datetime import datetime
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve, auc

def evaluate_model(model, X_test, y_test, model_name, output_dir):
    """
    Evaluate a trained model and save evaluation metrics
    
    Args:
        model: The trained scikit-learn model
        X_test: Test features
        y_test: Test labels
        model_name: Name of the model
        output_dir: Directory to save evaluation results
    """

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Make predictions
    y_pred = model.predict(X_test)
    if hasattr(model, "predict_proba"):
        y_pred_proba = model.predict_proba(X_test)[:, 1]
    else:
        y_pred_proba = model.decision_function(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    # ROC curve and AUC
    fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
    roc_auc = auc(fpr, tpr)
    
    # Compile metrics
    metrics = {
        "model_name": model_name,
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "auc": float(roc_auc),
        "evaluation_time": datetime.now().isoformat()
    }
    
    # Save metrics to file
    with open(f"{output_dir}/{model_name}_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    
    # Plot confusion matrix
    plt.figure(figsize=(8, 6))
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title(f'Confusion Matrix - {model_name}')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.savefig(f"{output_dir}/{model_name}_confusion_matrix.png")
    
    # Plot ROC curve
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='blue', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='gray', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title(f'ROC Curve - {model_name}')
    plt.legend(loc="lower right")
    plt.savefig(f"{output_dir}/{model_name}_roc_curve.png")
    
    # Plot feature importance (this is only if it available)
    if hasattr(model, "feature_importances_"):
        feature_names = X_test.columns if hasattr(X_test, "columns") else [f"feature_{i}" for i in range(X_test.shape[1])]
        feature_importances = pd.DataFrame({
            "feature": feature_names,
            "importance": model.feature_importances_
        }).sort_values("importance", ascending=False)
        
        # Save feature importances
        feature_importances.to_csv(f"{output_dir}/{model_name}_feature_importances.csv", index=False)
        
        # Plot top 20 features
        plt.figure(figsize=(10, 8))
        sns.barplot(x="importance", y="feature", data=feature_importances.head(20))
        plt.title(f'Top 20 Feature Importances - {model_name}')
        plt.tight_layout()
        plt.savefig(f"{output_dir}/{model_name}_feature_importances.png")
    
    return metrics