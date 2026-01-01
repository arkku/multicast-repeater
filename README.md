# multicast-repeater

A simple program to listen on IPv4 and IPv6 multicast groups on specified
interfaces and repeat/duplicate the packets to other interfaces. For
example, to allow mDNS service discovery across VLAN boundaries. Interfaces
can be specified as input only (listen on), output only (repeat to), or
both (the default).

The packets are preserved exactly as they are, other than the source address
is changed to the address of the output interface. (The address can be
overridden for specific interfaces is desired.)

I made this with the help of AI because Avahi seems to modify the packets
and this causes some issues with more picky IoT devices.

Note that this does not do anything for broadcast or unicast packets;
another reflector (or nftables `dup` rule) is needed for those. And you still
need to run Avahi (without reflector) if you wish to be discoverable.

~ [Kimmo Kulovesi](https://github.com/arkku/), 2026-01-01

## Installation

To build, have Go installed (e.g., `apt install golang`) then `make` (or just
`go build`). There is a convenience target `make install` to copy the binary to
`/usr/local/bin` but you can of course just put it anywhere.

See [mdns-repeater.service](mdns-repeater.service) for an example systemd unit
and modify it to suit your needs. Put it in `/etc/systemd/system`, then run
`systemctl daemon-reload` and `systemctl start mdns-repeater.service`. Or use
whatever you use to run stuff in the background, if not systemd.

## Usage

The basic use is to list comma-separated interfaces after `-i`, or you can use
`-4` and/or `-6` to have separate lists of interfaces for IPv4 and IPv6 (there
can be overlap).

If you need undirectional repeating, you can add `=in` or `=out` after the
interface name, e.g., `lan-main=out,lan-iot=in` would only repeat from `lan-iot`
to `lan-main`, not the other way around. (In case there are only two interfaces
the other label is technically redundant, but recommended anyway.)

The default protocol (including port and multicast groups) is mDNS. You can use
the option `-protocol` to specify other presets, like `-protocol ssdp`. Or you
can specify arbitrary ports with `-p` and multicast groups with `-group4`
and/or `-group6`, e.g., `-group4 224.0.0.251 -p 5353`. Note that specifying only
IPv4 or IPv6 group does NOT disable the other address family: if you want
only IPv4, use `-4` or `-6` to list the interfaces.

By default the program binds to the multicast group addresses. This works on
Linux, but if you need to bind to the wildcard address, you can do that with
the option `-wildcard` (this still discards packets received on other
interfaces). This is largely untested, though.

You can verify the repeat is working with the `-v` option to add verbosity
(prints a line for every repeated packet). The program does not fork, it is
meant to be used as a systemd unit or similar.

There are some other options that you can view with `--help`. You can also view
the list of protocol presets there.

## Examples

### mDNS

mDNS is the default mode. Simply list your interfaces after `-i` for both IPv4
and IPv6.

```
multicast-repeater -i lan-main,lan-iot,lan-admin
```

Or, if you have VLANs that are IPv4 only, in this example `lan-admin` uses only
IPv4 (note that `-i` expects both to be available and fails if one isn't):

```
multicast-repeater -4 lan-main,lan-iot,lan-admin -6 lan-main,lan-iot 
```

### SSDP

SSDP might not need to go both ways, in this example the interface `lan-iot` is
only used as an input (i.e., make devices on that VLAN discoverable on others,
but not able to discover devices on other VLANs).

```
multicast-repeater -i lan-main,lan-iot=in,lan-admin -protocol ssdp
```
