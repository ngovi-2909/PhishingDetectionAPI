FROM python:3.12


RUN mkdir -p "/var/www/phishingDetectionAPI"

COPY . /var/www/phishingDetectionAPI

WORKDIR /var/www/phishingDetectionAPI

RUN pip install -r requirement.txt

EXPOSE 8080

CMD ["python3", "manage.py", "runserver", "0.0.0.0:8080"]