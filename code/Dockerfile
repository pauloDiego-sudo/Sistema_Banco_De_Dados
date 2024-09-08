# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Install postgresql-client
RUN apt-get update && apt-get install -y postgresql-client

# Copy the requirements file into the container at /app
COPY requirements.txt /app/

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . /app

# Make port 80 available to the world outside this container
EXPOSE 80

# Define environment variable
ENV NAME FastAPIApp

# Run app.py when the container launches
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80","--reload"]