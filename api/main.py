import uvicorn

from environment import HOST, PORT, RELOAD

if __name__ == "__main__":
    uvicorn.run("app:app", host=HOST, port=PORT, reload=RELOAD, log_config=None)
