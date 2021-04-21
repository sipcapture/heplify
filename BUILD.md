### HEPLIFY Development

heplify can be compiled and built as follows:

#### Using make
If you have Go 1.11+ installed, build the latest heplify binary by running `make`.

----------

#### Using docker
If you have Docker, build the latest heplify binary as follows:

```bash
docker build --no-cache -t sipcapture/heplify:latest -f docker/heplify/Dockerfile .
```

----------

#### Manual
##### Linux (static)
```
build_static.sh
```
##### Linux (dynamic)
```
env GOOS=linux GOARCH=amd64 go build -v github.com/sipcapture/heplify
```
##### Windows (dynamic)
```
env GOOS=windows GOARCH=amd64 go build -v github.com/sipcapture/heplify
```
