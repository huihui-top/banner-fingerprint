# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.0-alpine AS build
WORKDIR /src
ENV GOTOOLCHAIN=local
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

FROM scratch AS server
WORKDIR /app
COPY --from=build /out/server /app/server
COPY rules /app/rules
ENV RULES_FILE=/app/rules/fingerprints.json
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/server"]
CMD ["serve"]

FROM scratch AS client
WORKDIR /app
COPY --from=build /out/client /app/client
USER 65532:65532
ENTRYPOINT ["/app/client"]
