FROM python:3.10-slim

WORKDIR /app

ENV FLASK_ARGS=""

COPY . .

RUN apt update -y && apt install -y build-essential && \
    pip install -r requirements.txt

ENTRYPOINT python3 -m flask run ${FLASK_ARGS}