# Step 1: Build the Go application
FROM golang:1.22 AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# Step 2: Create the Distroless container
FROM gcr.io/distroless/base-debian12

# Copy the binary from the builder stage
COPY --from=builder /app/main /app/main

# Command to run the executable
ENTRYPOINT ["/app/main"]