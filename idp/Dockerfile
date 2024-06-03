FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    firefox-esr \
    x11-apps

WORKDIR /app

COPY . .

RUN pip install -r requirements.txt

ENTRYPOINT python3 app.py LOAD_CLIENTS