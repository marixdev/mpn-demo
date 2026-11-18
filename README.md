# Mini Panel demo

The public demo at https://demo.mpanel.biz. It runs the real Mini Panel web interface, taken unchanged from the
`mini-panel` submodule, against a pretend server:

- `main.go` answers what the panel would ask its root helper (`mpn root`) from sample data. Adding a website or a
  firewall rule changes the sample data; every other change only reports success.
- `sshfake.go` answers the SSH logins of the Files and Terminal tabs. Files live in memory; the terminal is a small
  pretend shell. Nothing reaches the machine's files or programs.
- Everything resets every hour. The sign-in is `demo` / `demo-mini-panel`, shown on the sign-in page.
  Changing the password and the two-step sign-in are refused, so no visitor can lock the others out.

## Build

```sh
git clone --recurse-submodules git@github.com:marixdev/mpn-demo.git
cd mpn-demo
./build.sh            # ./mpn-demo for linux/amd64; GOARCH=arm64 ./build.sh for ARM
```

To show a newer panel, move the submodule and rebuild:

```sh
git -C mini-panel fetch --tags && git -C mini-panel checkout v1.2.2
./build.sh && git commit -am "demo: mini-panel v1.2.2"
```

The pages call root-helper operations by name (`site.list`, `firewall.add`...). A new page in mini-panel that uses an
operation `call` in `main.go` does not know gets the generic "done" answer; add a case when the page needs data.

## Run on the server

The demo runs on bay.onl (161.248.146.69) behind the panel's own nginx:

1. `install -m 0755 mpn-demo /usr/local/bin/mpn-demo`
2. `cp deploy/mpn-demo.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now mpn-demo`
3. In Mini Panel on that server: add a website `demo.mpanel.biz` of kind **proxy** to `http://127.0.0.1:8790`, then
   turn on SSL. The proxy vhost passes the WebSocket headers the terminal needs.

The service runs as a throw-away user (`DynamicUser`), with the system read-only and 256 MB of memory at most.

Try it locally: `go run` is not possible because of the overlay, so build for your own system
(`GOOS=windows ./build.sh` on Windows) and run `./mpn-demo -listen 127.0.0.1:8790 -host localhost -secure=false`.
