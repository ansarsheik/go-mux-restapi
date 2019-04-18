# Dockerfile References: https://docs.docker.com/engine/reference/builder/

# Start from golang v1.11 base image
FROM golang:1.11 as builder

# Add Maintainer Info
LABEL maintainer="a"

# Set the Current Working Directory inside the container
WORKDIR $GOPATH/src/api

# Copy everything from the current directory to the PWD(Present Working Directory) inside the container
COPY . .

# Download all the dependencies
# https://stackoverflow.com/questions/28031603/what-do-three-dots-mean-in-go-command-line-invocations
RUN go get -d -v ./...

# Install the package
RUN go install -v ./...

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o goworker .

# This container exposes port 8080 to the outside world
#EXPOSE 1234

# Run the executable
#CMD ["./goworker"]

#
FROM scratch
COPY --from=builder /go/src/api/goworker /app/
WORKDIR /app
EXPOSE 1234
CMD ["./goworker"]