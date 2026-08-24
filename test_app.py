from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def home():
    return {
        "message": "Protected application is working"
    }


@app.get("/hello")
def hello():
    return {
        "message": "Hello from the protected application"
    }
