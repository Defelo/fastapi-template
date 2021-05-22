#!/bin/sh

uvicorn --app-dir api app:app --host ${HOST:-0.0.0.0} --port ${PORT:-8000} $@
