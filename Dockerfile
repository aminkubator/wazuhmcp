# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /wazuhmcp . && mkdir /data

# static binary only: no shell, runs as uid 65532
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /wazuhmcp /wazuhmcp
# volume inherits this ownership, so the nonroot user can write the audit log
COPY --from=build --chown=65532:65532 /data /data
ENV WAZUHMCP_ADDR=0.0.0.0:8090 \
    WAZUHMCP_AUDIT_FILE=/data/audit.jsonl
VOLUME /data
EXPOSE 8090
ENTRYPOINT ["/wazuhmcp", "serve"]
