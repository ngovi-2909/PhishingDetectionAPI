import joblib

from train_model import Phishing_detection


class PredictRepository:
    def __init__(self):
        self.model = joblib.load('train_model/random_forest_model.sav')

    def get_model(self):
        return self.model
