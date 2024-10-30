FROM python:3.10-bullseye
LABEL maintainer="Jabba"

ENV PYTHONUNBUFFERED 1

## Install dependencies (before copying the app to use cache)
COPY ./django-build/requirements.txt /requirements.txt
RUN python -m venv /py && \
    /py/bin/pip install --upgrade pip && \
    /py/bin/pip install --no-cache-dir -r /requirements.txt

COPY ./app /app
COPY ./django-build/scripts /scripts

WORKDIR /app
EXPOSE 8000

RUN adduser app && \
    mkdir -p /vol/web/static && \
    mkdir -p /vol/web/media && \
    chown -R app:app /vol && \
    chmod -R 755 /vol && \
    chmod -R +x /scripts

ENV PATH="/scripts:/py/bin:$PATH"

USER app

CMD [ "run.sh" ]