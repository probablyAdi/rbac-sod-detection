# Use a minimal base image with g++
FROM gcc:latest

# Set the working directory inside the container
WORKDIR /app

# Copy all necessary files to the container
COPY . .

# Compile the C++ program
RUN g++ -o PrivilegeAnalyzer PrivilegeAnalyzer.cpp -pthread

# Define the command to run the program
CMD ["./PrivilegeAnalyzer"]
