from rest_framework import serializers
from .models import Predict


class PredictionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Predict
        fields = '__all__'
