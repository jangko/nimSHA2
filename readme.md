# nimSHA2

![Github action](https://github.com/jangko/nimSHA2/workflows/nimSHA2%20CI/badge.svg)

### Secure Hash Algorithm 2
##### 224, 256, 384, and 512 bits

initially this was part of [nimPDF](https://github.com/jangko/nimpdf) project, then I decided to release it separately

example:

```nimrod
var sha = initSHA[SHA256]()
sha.update("test SHA256")
let digest = sha.final()
```

or:
```nimrod
let digest = computeSHA256("test SHA256")
```

**conversion:**

- to convert digest into string, use proc $
- to convert digest into hex string, use toHex

each version of  SHA2 hash function will produce output according to it's name: SHA224 produce 224 bits hash, SHA256 produce 256 bits hash, and so on

already tested with test vector from [here](http://www.di-mgt.com.au/sha_testvectors.html), see `tests/test.nim`
