# filename: app.py
# run cmd: python3 -m flask run -p 8080

from flask import Flask
from logging.config import dictConfig
import time

# flask logging:
# https://flask.palletsprojects.com/en/2.3.x/logging/
dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)
if __name__ == '__main__':
    app.run(threaded=True)

@app.route("/")
def hello_world():
    time.sleep(5)
    return "<p>Hello, World!</p>"