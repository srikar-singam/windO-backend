FROM python:3.8.1

MAINTAINER Rudradev Pal

# Create working directory
RUN mkdir -p /app

# Define working directory
WORKDIR /app

# Copy Current Directory data
ADD . /app

# Install Dependency
RUN pip install -r requirements.txt

# Run Application
CMD python app.py