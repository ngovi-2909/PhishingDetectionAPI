from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import PredictionSerializer
from train_model import Phishing_detection
from .service.PredictRepository import PredictRepository
import re
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
    print(item)
    if item.is_valid():
        # item.save()
        domain = check_domain_or_url(item.data.get('domain'))
        predict_model = model.get_model()
        result = Phishing_detection.predict(predict_model, domain)
        return Response({"data": result}, status=status.HTTP_201_CREATED)
    else:
        return Response(item.errors, status=status.HTTP_400_BAD_REQUEST)


def check_domain_or_url(input_string):
    url_regex = r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"

    if re.match(url_regex, input_string):
        return input_string
    else:
       return "https://" + input_string
