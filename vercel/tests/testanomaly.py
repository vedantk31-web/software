import sys
import os

# Get the absolute path to the parent directory of the current file (test_key.py)
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)

# Append the parent directory to sys.path
sys.path.append(parent_dir)
import unittest
import numpy as np
from sklearn.ensemble import IsolationForest  # Import IsolationForest class
from anomaly_detection import train_anomaly_detection, predict_anomaly

class TestAnomalyDetection(unittest.TestCase):
    def test_train_anomaly_detection(self):
        # Generate some dummy data for testing
        data = np.random.rand(100, 10)
        # Train the anomaly detection model
        model = train_anomaly_detection(data)
        # Check that the model is an instance of IsolationForest
        self.assertIsInstance(model, IsolationForest)

    def test_predict_anomaly(self):
        # Generate some dummy data for testing
        data = np.random.rand(100, 10)
        model = IsolationForest(contamination=0.01)
        model.fit(data)
        # Generate new dummy data for prediction
        new_data = np.random.rand(1, 10)
        # Predict anomalies
        prediction = predict_anomaly(model, new_data)
        # Check that the prediction is either 1 (normal) or -1 (anomaly)
        self.assertIn(prediction, [-1, 1])

if __name__ == '__main__':
    unittest.main()
