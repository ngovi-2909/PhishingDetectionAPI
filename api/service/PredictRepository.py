from train_model import Phishing_detection


class PredictRepository:
    def __init__(self):
        self.model = Phishing_detection.train_data()

    def get_model(self):
        return self.model
