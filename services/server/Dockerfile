# pull official base image
FROM python:3.9.5-slim-buster

# set work directory
WORKDIR /app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
RUN pip install --upgrade pip
COPY ./requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt

# copy project
COPY . /app/

# run entrypoint
RUN SECRET_KEY=$(chars='abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'; python -c "import secrets; print(''.join(secrets.choice('${chars}') for i in range(50)))")
CMD ["python3 app.py"]