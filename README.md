# Low Weight cipher library

| CipherType | key size(bits) | block_size(B) | MODE        |
|------------|----------------|---------------|-------------|
| XTEA       | 128            | 8             | ECB,CBC,CTR |
| XXTEA      | 128            | 8             |             |
| SIMON      | ...            |               |             |
| SPECK      | ...            |               |             |
| PRESENT    | 80 or 128      | 8             |             |

**SIMON:**  various block sizes and key sizes

| Block size (bits) | Key size (bits) | Rounds |
|-------------------|-----------------|--------|
| 32                | 64              | 32     |
| 48                | 72              | 36     |
| 96                | 36              |        |
| 64                | 96              | 42     |
| 128               | 44              |        |
| 96                | 96              | 52     |
| 144               | 54              |        |
| 128               | 128             | 68     |
| 192               | 69              |        |
| 256               | 72              |        |

**SPECK:**  various block sizes and key sizes

| Block size (bits) | Key size (bits) | Rounds |
|-------------------|-----------------|--------|
| 2×16 = 32         | 4×16 = 64       | 22     |
| 2×24 = 48         | 3×24 = 72       | 22     |
| 4×24 = 96         |                 | 23     |
| 2×32 = 64         | 3×32 = 96       | 26     |
| 4×32 = 128        |                 | 27     |
| 2×48 = 96         | 2×48 = 96       | 28     |
| 3×48 = 144        |                 | 29     |
| 2×64 = 128        | 2×64 = 128      | 32     |
| 3×64 = 192        |                 | 33     |
| 4×64 = 256        |                 | 34     |

## Usage

```shell
# to build the library
mkdir cmake-build-debug
cd cmake-build-debug
cmake ..
make
```

```shell
# to install the library
sudo make install
```

```shell
# to uninstall the library
sudo make uninstall
```

The library will be installed in `/usr/local/lib` and the header files will be installed in `/usr/local/include`.

