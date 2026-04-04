FROM alpine:3.21

RUN apk add --no-cache ca-certificates git && \
    adduser -D -h /home/supplyguard supplyguard

COPY supply-guard /usr/local/bin/

USER supplyguard

ENTRYPOINT ["supply-guard"]
