# SimpleDnsServer

A simple DNS server that supports A (IPv4), AAAA (IPv6) and PTR (reverse lookup) queries.

## Installation

A simple makefile is included in the project. Run the `make` command to compile. `make install` will install the executable in /usr/local/bin by default. For cross-compilation or custom compilers, set the environment variable CXX and CFLAGS with the required value.

```bash
make           ## compile only
make install   ## install to /usr/local/bin
```
The install path can be overridden using the PREFIX environment variable.

```bash
PREFIX=/home/asd/bin make install
```

## Usage

```
SimpleDnsServer <-f entires_file> [-p port_num] [-d] [-v]
```

| Option | Argument     | Description                                                            |
|--------|--------------|------------------------------------------------------------------------|
| f      | entries_file | Path to the entries file. Check Entries file section for more details. |
| p      | port_num     | Port number on which to listen for requests. Default is port 53.       |
| d      | -            | Daemonize the program. Logs get redireced to syslog.                   |
| v      | -            | Verbose mode                                                           |

_Example:_
```bash
./SimpleDnsServer -f dns_entries.conf
```


## Entries file
The entries file contains IP addresses and hostname pairs separated by a space. Current version doesn't support replying with multiple IPs for a single PTR query.

_Example:_
```
asdf.com 1.2.3.4
qwertyuiop.com 2001:b19::678:89ab
somesite.org 2.3.4.5
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
Distributed under the MIT License. See LICENSE file for more information.

