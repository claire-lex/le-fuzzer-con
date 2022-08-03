Le fuzzer con
=============

![Licence](https://img.shields.io/github/license/claire-lex/le-fuzzer-con)

Le Fuzzer Con* (LFC) creates network packets as random byte arrays that are sent
to a server to fuzz it. The thing with LFC is that we can lock bytes that should
not be random (e.g. a valid header). The aim is to create packets that are not
directly dropped by servers, so that our fuzzed frames reach the parsing and
processing implementations and cover more code. LFC keeps no track of previous
packets (it's just random) and gives no feedback about what happens server-side,
you have to monitor it yourself.

> *"Le fuzzer con" means "The dumb fuzzer" in French, because it is meant to be
  dumb (i.e. stateless and protocol-independent). f you want a fine-tuned
  fuzzing process, I recommend you use a real fuzzer instead.

TL;DR
-----

```
make
./le-fuzzer-con udp://192.168.1.100:4444 -l "0:\x01\x01;4:\xLL\xLL" -m 6 -n 20
-d 1
```

This command :

* Creates almost-random packets from 6 to 20 bytes long
* Packets always start with 0101 and have the total packet length on 2 bytes
  written on bytes 4 et 5
* They are sent via UDP to 192.168.1.100 on port 4444 every 1 millisecond.

Usage
-----

```
  host            Target information with format proto://ip:port.
                  Ex: udp://192.168.1.1:3671

Arguments:
  -l    --lock    List of fixed bytes (same for all packets) Format is:
                  location1:content1;loc2:con2;... Content can also be a keyword.
                  (eg: 0:\x06\x10\xLL\xLL;-1:\x01 -> Header on 4B ending with
                  total packet length on 2B, last byte is always \x01)
  -m    --min     Minimum size for packets (default: 1).
  -n    --max     Maximum size for packets (default: 20 (arbitrary)).
  -d    --delay   Delay in ms before sending the next packet (default: 0).
  -s    --step    Step by step mode, wait for user input to send the next frame.
  -v    --verbose Verbose mode.
```

**lock** is the most important argument to use, to set the location and content
of bytes that should not change. You can define many locks, delimited with `;`.

Location and content's format is: `location:content` where:

* `location` is the offset in the byte array (starting from 0). If < 0, it's the
  position from the end of the string (e.g.: -1 == the last byte of the
  packet)

* `content` is the byte or byte array to set with format `\x00` or `00`. `content`
  can also contain the total length of the packet on one or several bytes with
  syntax `LL`. For instance, to set the total length on 2 bytes: `\xLL\xLL` or
  `LLLL`

Examples:

* `0:\x06\x10`: All packets start with `\x06\x10`.
* `1:\xff;3:\xff`: The second and forth bytes are set to `\xff`.
* `0:\x06\x10;4:\xLL\xLL`: Each packet starts with `\x06\x10`, bytes 4-5 contain
  the total length of the packet.
* `-2:\xLL\xLL`: All packets end with length modifier on 2 bytes.
* `0:\x01;-1:\x01`: Packets always start and end with `\x01`.

TODO and ideas
--------------

* [ ] Refactoring: `insert_locks` and `insert_length`
* [ ] Listen for responses from the server.
* [ ] Send a pre and/or post request before sending the fuzzed one.
* [ ] Replace random with a set of choices for some bytes.
* [ ] Extract base frames from pcap files, tell which bytes should not be
      changed (`0:\x==\x==`: first 2 bytes always kept as is).
* [ ] Option to use radamsa for mutations with pcap mode?
* [ ] Improve output (nice terminal with ncurses and stats and all).
* [X] BUGFIX: `-l "-2:\xLL;-1:\x11"`
* [X] `--delay` option to add a delay (in ms) between each frame.
* [X] `lock`: Set `location` from the end of the packet.
* [X] `lock`: Set length modifier's location from the end of the packet.
* [X] `lock`: Make `content` be the total length of the packet, on 1+ byte(s).