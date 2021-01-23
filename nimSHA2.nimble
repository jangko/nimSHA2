# Package
version       = "0.1.1"
author        = "Andri Lim"
description   = "SHA2 secure hash algorithm - 2 - [224, 256, 384, 512 bits]"
license       = "MIT"
skipDirs     = @["tests", "docs"]

# Deps
requires "nim >= 0.11.2"

### Helper functions
proc test(env, path: string) =
  # Compilation language is controlled by TEST_LANG
  var lang = "c"
  if existsEnv"TEST_LANG":
    lang = getEnv"TEST_LANG"

  exec "nim " & lang & " " & env &
    " -r --hints:off --warnings:off " & path

task test, "Run tests":
  test "-d:release", "tests/test"

task testvcc, "Run tests with vcc compiler":
  test "--cc:vcc -d:release", "tests/test"
