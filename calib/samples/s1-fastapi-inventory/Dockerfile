FROM python:latest
RUN curl -fsSL https://get.example-cli.dev/install | bash
COPY . /app
CMD ["uvicorn", "main:app"]
