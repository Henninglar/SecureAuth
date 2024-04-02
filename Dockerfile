# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt
RUN pip install flask-limiter  # Add this line to install flask-limiter
# Install SQLite
RUN apt-get update && apt-get install -y sqlite3
# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable
ENV FLASK_APP=app.py

# Run app.py when the container launches on port 5000
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
