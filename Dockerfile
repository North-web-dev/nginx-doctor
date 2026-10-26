FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/nginx-doctor ./cmd/nginx-doctor

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nginx-doctor /usr/local/bin/nginx-doctor
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/nginx-doctor"]
