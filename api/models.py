from django.db import models


# Create your models here.
class Predict(models.Model):
    domain = models.CharField(max_length=255)

    def __str__(self):
        return self.domain
