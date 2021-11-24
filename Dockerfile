FROM python:3.9.7-alpine AS builder

RUN apk add --no-cache \
    build-base~=0.5 \
    gcc~=10.3 \
    musl-dev~=1.2 \
    libffi-dev~=3.3 \
    postgresql-dev~=13.5 \
    git~=2.32

WORKDIR /build

RUN pip install pipenv==2020.11.15

COPY Pipfile /build/
COPY Pipfile.lock /build/

ARG PIPENV_NOSPIN=true
ARG PIPENV_VENV_IN_PROJECT=true
RUN pipenv install --deploy --ignore-pipfile

COPY api/version.py /build/
COPY .git /build/.git/
RUN python version.py


FROM python:3.9.7-alpine

LABEL org.opencontainers.image.source="https://github.com/Defelo/fastapi-template"

WORKDIR /app

RUN set -x \
    && apk add --no-cache curl~=7.79 libpq~=13.5 \
    && addgroup -g 1000 api \
    && adduser -G api -u 1000 -s /bin/sh -D -H api

USER api

EXPOSE 8000

COPY --from=builder /build/.venv/lib /usr/local/lib
COPY --from=builder /build/VERSION /app/

COPY api /app/api/

HEALTHCHECK --interval=20s --timeout=5s --retries=1 \
    CMD curl -fI http://localhost:${PORT:-8000}/status

CMD ["python", "-m", "api"]
