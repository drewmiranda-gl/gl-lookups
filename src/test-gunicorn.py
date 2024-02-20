# python3 -m gunicorn -w 4 test-gunicorn:app --bind=127.0.0.1:8080

import time

def app(environ, start_response):
    time.sleep(5)
    data = b"Hello, World!\n"
    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("Content-Length", str(len(data)))
    ])
    return iter([data])