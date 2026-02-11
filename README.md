# NextSSL

**A private Layline for proper security it's server, ai, human or your pet frog**









now litsen
we need a system to implent some basic things
like server will ask client fro pow in a formate like
it will give client a code self explanatory which will contain main bytes/codes what will be pow with
then we need algo and prefix and prefix if not 0 but something else that also have to be described
and client side when return the value that must be super easy to retest by server to make sure the pow done or not

sop for that i need
```
utils/
└── encoding/
    ├── hex.c
    ├── base64.c
    ├── base64url.c
    ├── base32.c (optional)
    └── bech32.c (optional)
```
perpus
```
Hex encode/decode
Base64 encode/decode
Base64URL encode/decode
Base32
Bech32 (if human-entered keys / PoW puzzles)
```

and a new algo will be there too, read name is FF70 (FlexFrame70) so make sure do it propeerly and it must be independently moveable (bcz it will be in utils but blake 3 as hash is in hash dirs so use that blake3 from the hash dirs where that is)




also i forgot to tell you that we need all of those 4 file also in /src/utils/pow/server and those upper all file in section 2 a,b,c are client side interfaces so server will actually have few interface
one is challenge phase
in sererver we will have 