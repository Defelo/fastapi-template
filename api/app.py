from fastapi import FastAPI

app = FastAPI()


@app.on_event("startup")
async def on_startup():
    pass


@app.on_event("shutdown")
async def on_shutdown():
    pass


@app.get("/test")
async def test():
    return {"result": "hello world"}
