FROM python:3.10-alpine AS builder

RUN apk add --no-cache \
    build-base~=0.5 \
    gcc~=10.3 \
    musl-dev~=1.2 \
    libffi-dev~=3.4 \
    postgresql14-dev~=14.1 \
    git~=2.34

WORKDIR /build

RUN pip install pipenv==2021.11.23

COPY Pipfile /build/
COPY Pipfile.lock /build/

ARG PIPENV_NOSPIN=true
ARG PIPENV_VENV_IN_PROJECT=true
RUN pipenv install --deploy --ignore-pipfile

COPY api/version.py /build/
COPY .git /build/.git/
RUN python version.py


FROM python:3.10-alpine

LABEL org.opencontainers.image.source="https://github.com/Defelo/fastapi-template"

WORKDIR /app

RUN set -x \
    && apk add --no-cache curl~=7.80 libpq~=14.1 \
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
