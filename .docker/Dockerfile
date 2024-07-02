# The builder image, used to build the virtual environment
FROM python:3.11-buster as builder

RUN pip install poetry==1.4.2

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_VIRTUALENVS_OPTIONS_NO_PIP=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache \
    POETRY_VIRTUALENVS_PATH=/venvs \
    VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH"

WORKDIR /venvs

COPY pyproject.toml poetry.lock ./

RUN --mount=type=cache,target=$POETRY_CACHE_DIR poetry install --without test,linters --no-root

# The runtime image, used to just run the code provided its virtual environment
FROM python:3.11-slim-buster as runtime

WORKDIR /app
ARG VERSION

ENV VIRTUAL_ENV=/venvs/.venv \
    PATH="/venvs/.venv/bin:$PATH" \
    VERSION=${VERSION:-beta}

RUN set -eux; apt-get update -y && apt-get install netcat --no-install-recommends -y
COPY app /app
COPY pyproject.toml /

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}
