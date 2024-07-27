FROM golang:1.22-bookworm AS build

WORKDIR /app

COPY . ./
RUN make


FROM debian:bookworm

COPY --from=build /app/bin/* /bin

EXPOSE 80 443 4443

CMD [ "/bin/ngroxd" ]
