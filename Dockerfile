ARG GOVERSION=latest
FROM golang:$GOVERSION AS builder

WORKDIR /src
COPY . .

ENV CGO_ENABLED=0
RUN rm -f roadmap-votes && go build -v

FROM alpine

EXPOSE 8080
ENV LISTEN_ADDRESS=:8080

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /src/roadmap-votes /bin/roadmap-votes

ENTRYPOINT ["/bin/roadmap-votes"]

