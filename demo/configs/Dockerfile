FROM python:3.11-slim

ENV DEBUG=true
ENV API_SECRET=hardcodedDockerSecret123
ENV DATABASE_PASSWORD=dbPassw0rd!

WORKDIR /app
RUN apt-get update && apt-get install -y curl && curl -sSL https://example.com/install.sh | bash
COPY . /app

EXPOSE 8000
CMD ["python", "app.py"]
