from sklearn.ensemble import IsolationForest

def train_anomaly_detection(data):
    model = IsolationForest(contamination=0.01)
    model.fit(data)
    return model

def predict_anomaly(model, new_data):
    return model.predict(new_data)
