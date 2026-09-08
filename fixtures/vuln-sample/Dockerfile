FROM python:latest
RUN curl -sSL https://get.example-tooling.io/install.sh | sh
COPY . /app
RUN pip install -r /app/requirements.txt
CMD ["python", "/app/app.py"]
