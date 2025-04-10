from fastapi import FastAPI,Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles


app=FastAPI()
templates=Jinja2Templates(directory="templates")
app.mount("/static",StaticFiles(directory="static"),"static")

@app.get('/')
def hello_world(request:Request):
    return templates.TemplateResponse("index.html",{"request":request})


