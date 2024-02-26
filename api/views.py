from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import PredictionSerializer
from train_model import Phishing_detection
from .service.PredictRepository import PredictRepository

# Create your views here.

model = PredictRepository()


@api_view(['GET'])
def ApiOverview(request):
    api_urls = {
        'predictURL': '/predict',
    }
    return Response(api_urls)


@api_view(['POST'])
def predict_url(request):
    item = PredictionSerializer(data=request.data)

    if item.is_valid():
        # item.save()
        domain = item.data.get('domain')
        predict_model = model.get_model()
        result = Phishing_detection.predict(predict_model, domain)
        return Response({"data": result}, status=status.HTTP_201_CREATED)
    else:
        return Response(item.errors, status=status.HTTP_400_BAD_REQUEST)
