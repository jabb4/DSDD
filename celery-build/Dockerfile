FROM python:3.10-bullseye
LABEL maintainer="Jabba"

ENV PYTHONUNBUFFERED 1

## Install dependencies (before copying the app to use cache)
COPY ./celery-build/requirements.txt /requirements.txt
RUN python -m venv /py && \
    /py/bin/pip install --upgrade pip && \
    /py/bin/pip install --no-cache-dir -r /requirements.txt

COPY ./app /app
COPY ./celery-build/scripts /scripts

WORKDIR /app

RUN adduser celery && \
    chmod -R +x /scripts

ENV PATH="/scripts:/py/bin:$PATH"

USER celery

CMD [ "run.sh" ]
