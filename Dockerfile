FROM python:3.13.3

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

COPY . /app

CMD ["fastapi", "run", "/app/main.py", "--port", "8000", "--proxy-headers"]
