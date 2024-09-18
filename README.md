# Sistema Médico

This project is a medical appointment management system built with FastAPI and PostgreSQL.

## Prerequisites

- Python 3.8+
- Docker and Docker Compose

## Setup

1. Clone the repository:
   ```
   git clone <repository-url>
   cd <project-directory>
   ```

2. Create a `.env` file in the project root with the following content:
   ```
   DATABASE_URL=postgresql://bonetti:1762@db/sistema_medico
   ```

3. Build and start the Docker containers:
   ```
   docker-compose up --build
   ```

4. Once the containers are running, populate the database with sample data:
   ```
   docker-compose exec web python code/popular_banco.py
   ```

## Usage

The API will be available at `http://localhost:8000`. You can use tools like cURL, Postman, or a web browser to interact with the API endpoints.

### API Documentation

FastAPI automatically generates interactive API documentation. You can access it at:

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Authentication

To use most endpoints, you need to authenticate first. Use the `/token` endpoint to obtain a JWT token:

