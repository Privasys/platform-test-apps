# container-app-wireguard-split

An app that reaches one private API through a WireGuard tunnel, while every
other connection goes out directly.

The tunnel runs in userspace ([wireguard-go](https://git.zx2c4.com/wireguard-go)
with its gVisor netstack). An app container has no `CAP_NET_ADMIN` and no
`/dev/net/tun`, so it cannot create a network interface or change routes. The
tunnel is a dialer instead, and only the private API's HTTP client uses it.

## Configure

The settings arrive through `POST /configure` (owner only), never in the image:

```json
{
  "private_key": "<this app's WireGuard private key, base64>",
  "peer_public_key": "<the server's public key, base64>",
  "preshared_key": "<optional, base64>",
  "endpoint": "vpn.example.org:51820",
  "address": "10.66.66.8",
  "allowed_ip": "10.66.66.1/32",
  "private_url": "http://10.66.66.1:18080/",
  "direct_url": "https://example.org/"
}
```

`allowed_ip` is the only prefix sent into the tunnel. For a real deployment,
also ask the VPN's owner to let this peer reach the API's host and port only.

## Probe

`GET /probe` makes three calls and reports each:

1. `direct_url` without the tunnel: succeeds.
2. `private_url` through the tunnel: succeeds.
3. `private_url` without the tunnel: fails, which shows the API is reachable
   only through the VPN.
