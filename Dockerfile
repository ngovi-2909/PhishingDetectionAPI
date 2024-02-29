FROM python:3.12

ENV PYTHONUNBUFFERED=1

WORKDIR /phishingDetectionAPI

COPY requirement.txt .

RUN pip install -r requirement.txt

COPY . .

EXPOSE 8080

CMD ["python3", "manage.py", "runserver"]