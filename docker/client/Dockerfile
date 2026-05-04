FROM alpine:3.20

RUN apk add --no-cache bind-tools curl iputils iproute2

COPY docker/client/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

CMD ["sleep", "infinity"]
