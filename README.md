# Domain Router

Reverse Proxy for routing subdomains to different ports on same host machine

## Configuration
```csv
test.pablu.de;8181
manga.pablu.de;8282
pablu.de;8080
<Url>;<local Port>
```

## Building

### Build executable
```sh
make build
```

### Runnging with default config
```sh
make run
```
