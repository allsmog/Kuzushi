FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /out/adapter ./...

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/adapter /adapter
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/adapter"]
