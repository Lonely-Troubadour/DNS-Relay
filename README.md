# DNS-Relay

DNS relay service program. BUPT junior summer practice project.

## Description

The DNS-relay program works as a relay server between local DNS resolver and public DNS server. It captures DNS queries from the local TCP channel, port 53. For example, using `nslookup` command. Afterwards it has the following functions,

1. DNS interception. Intercept the query according to the local database.
2. DNS relay. Respond to the query according to the local database or relay the query to the public DNS server.

## Build

```
$ cd path/to/dns-relay-folder
$ make
```

## Run

For Ubuntu, macOS, and Windows users, use

```
$ sudo ./dns-relay
```

to run the program. If the system is Windows, an administrative access is required.

## Usage
Usage: [commands] [options] \
Commands: \
&nbsp;&nbsp;&nbsp;&nbsp;    [-d|-dd], debug mode \
&nbsp;&nbsp;&nbsp;&nbsp;    [-s] <dns_server_addres> \
&nbsp;&nbsp;&nbsp;&nbsp;    [-p] <path_to_db_file> 

### Example: 
```
$ sudo ./dnsrelay -d -s 219.141.136.10 -p ./data/dnsrelay.txt
```

## Troubleshooting

For Ubuntu users, you may need to disable the system dns resolver first.

```
$ sudo systemctl stop systemd-resolved
```
