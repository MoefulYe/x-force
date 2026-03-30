# xforce

`xforce` runs a command inside an isolated rootless Linux network namespace and forces traffic through `tun2socks`.

## Runtime Dependencies

- `slirp4netns`

## Usage

```bash
xforce [-x <proxy_url>] [-d <tun_dev>] [--tun-cidr <cidr>] [-u <uplink_dev>] [-l <tun2socks_log>] [--slirp-log <file>] [--] <command> [args...]
```

Example:

```bash
xforce -x socks5://192.168.231.2:7905 -- curl -vvv www.baidu.com
xforce -x socks5://192.168.231.2:7905 --tun-cidr 192.168.239.1/24 -- curl -vvv www.baidu.com
```

## Build

```bash
CGO_ENABLED=0 go build -o main .
```

## Test

```bash
CGO_ENABLED=0 go test ./...
```

## Nix

```bash
nix build .#default
nix run .#xforce -- --version
nix develop
```
