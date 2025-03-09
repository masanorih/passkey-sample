FROM python:3.12
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update
RUN apt install -yq --no-install-recommends curl unzip
RUN pip install pip==24.0
RUN pip install pipenv==v2024.4.1
COPY Pipfile ./
COPY Pipfile.lock ./
# COPY app.py ./
RUN pipenv sync --dev
# flask default port to 5000
EXPOSE 5000
CMD ["pipenv", "run", "flask", "--debug", "run", "-h", "0.0.0.0"]
