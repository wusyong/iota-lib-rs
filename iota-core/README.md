To get iota_common (C static library), please build the target with following steps:

```
git clone https://github.com/oopsmonk/iota_common.git
cd iota_common && git co origin/bench_sign -b bench_sign
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=. -DBENCH_IOTA_COMMON=ON -DKERL_AVX2=ON -DKERL_SIMD256_AVX2uf=ON -DCMAKE_BUILD_TYPE=Release
make -j10
```

and move `libcomon.a` and `libkeccak.a` to `src/` directory