Le fuzzer con
=============

Another dumb network fuzzer, but not the worst one*.

Le fuzzer con creates packets as byte arrays that are sent to a server to fuzz
it. The content is random by default, but we can set bytes that should not be
random (e.g. a valid header). The aim is to create packets that are not directly
dropped by servers, so that our fuzzer reaches and starts testing the parsing
and processing implementations.

So far, le fuzzer con gives no feedback about what happens server-side, you have
to monitor it yourself.

> "Le fuzzer con" means "The dumb fuzzer" in French.

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
  -m    --min     Minimum size for packets.
  -n    --max     Maximum size for packets.
  -s    --step    Step by step mode, wait for user input to send the next frame.
  -v    --verbose Verbose mode.
```

**lock** is the most important argument to use, to set the location and content
of bytes that should not change. You can define many locks, delimited with `;`.

Location and content's format is: `location:content` where:

* `location` is the offset in the byte array. If < 0, it's the position from the
  end of the string (e.g.: -2 == the last 2 bytes of the packet)

* `content` is the byte or byte array to set with format `\x00` or `00`. `content`
  can also contain the total length of the packet on one or several bytes with
  syntax `LL`. For instance, to set the total length on 2 bytes: `\xLL\xLL` or
  `LLLL`

Examples:

* `0:\x06\x10`: Each packet starts with `\x06\x10` (content written starting
  from position 0).
* `1:\xff;3:\xff`: The second and forth bytes are set to `\xff`.
* `0:\x06\x10;4:\xLL\xLL`: Each packet starts with `\x06\x10`, bytes 4-5 contain
  the total length of the packet.
* `-2:\xLL\xLL`: All packets end with length modifier on 2 bytes.
* `0:\x01;-1:\x01`: Packets always start and end with `\x01`.

TODO
----

* [ ] BUGFIX: `-l "-2:\xLL;-1:\x11"`
* [ ] Network: Listen for responses from the server.
* [ ] Global: Improve output (nice terminal with ncurses and stats and all).
* [ ] Global : Ability to replace random with a set of choices.
* [ ] Refactoring: `insert_locks` and `insert_length`
* [X] `lock`: Set `location` from the end of the packet.
* [X] `lock`: Set length modifier's location from the end of the packet
* [X] `lock`: Make `content` be the total length of the packet, on 1+ byte(s).