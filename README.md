# OP-TEE Benchmarking Algorithms & Building Blocks of MQTT-TZ
## Contents
1. [Introduction](#1-introduction)
2. [List of Implemented Applications](#2-list-of-implemented-applications)


## 1. Introduction
This document describes the different benchmarking applciations developed with the Op-TEE framework together with the implemented min-apps that will pave the way for the MQTT-TZ implementation.

---
## 2. List of Implemented Applications

Directory **hello_world/**:
* A very simple Trusted Application to answer a hello command and incrementing
an integer value.
* Test application: `optee_example_hello_world`

Directory **aes/**:
* Runs an AES encryption and decryption from a TA using the GPD TEE Internal
Core API. Non secure test application provides the key, initial vector and
ciphered data.
* Test application: `optee_example_aes`
* Benchmarking: secure vs non secure encryption and decryption of a 4 kB piece of clear text. 100 times, report avg and std:

**Operation (100 Runs)** | `aes128 avg(ms)` | `aes128 stdev(ms^2)` | `aes256 avg(ms)` | `aes256 stdev(ms^2)`
----- | :-----: | :-----: | :-----: | :-----:
**`encrypt_secure`** | 10.015500 | 1.778416 | 9.904960 | 0.864986
**`encrypt_non_secure`** | 0.095030 | 0.400823 | 0.058830 | 0.042737
**`decrypt_secure`** | 9.975890 | 1.361816 | 9.838330 | 0.726974
**`decrypt_non_secure`** | 0.029540 | 0.066368 | 0.024580 | 0.011792

* Given the big difference in times, we do a detailed breakdown, call by call.

**Operation (100 Runs)** | `aes128 avg(ms)` | `aes128 stdev(ms^2)` | `aes256 avg(ms)` | `aes256 stdev(ms^2)`
----- | :-----: | :-----: | :-----: | :-----:
**ENCRYPT** | | | |
**`prepare_aes (All)`** | 1.835580 | 0.617803 | 1.735570 | 0.249139
**`prepare_aes (Inv)`** | 1.828620 | 0.602770 | 1.727980 | 0.247723
**`set_iv (All)`** | 1.771470 | 0.381386 | 1.745310 | 0.298647
**`set_key (All)`** | 2.013820 | 0.261122 | 1.993960 | 0.238595
**`set_key (Inv)`** | 2.497050 | 0.313976 | 2.493960 | 0.257539
**`cipher_buffer (All)`** | 2.489840 | 0.376701 | 2.489350 | 0.250265
**`cipher_buffer (Inv)`** | 3.186370 | 0.416062 | 3.146790 | 0.223447
**DECRYPT** | | | |
**`prepare_aes (All)`** | 1.776720 | 0.382576 | 1.750260 | 0.299260
**`prepare_aes (Inv)`** | 1.771470 | 0.381386 | 1.745310 | 0.298647
**`set_iv (All)`**  | 2.021380 |0.260658 | 1.998940 | 0.238969
**`set_iv (Inv)`** | 2.013820 | 0.261122 | 1.993960 | 0.238595
**`set_key (All)`** | 2.495490 | 0.377351 | 2.494840 | 0.250680
**`set_key (Inv)`**  | 2.489840 | 0.376701 | 2.489350 | 0.250265
**`cipher_buffer (All)`** | 3.143650 | 0.368956 | 3.125450 | 0.173279
**`cipher_buffer (Inv)`** | 3.137560 | 0.368027  | 3.119400 | 0.173166


Directory **secure_storage/**:
* A Trusted Application to read/write raw data into the
OP-TEE secure storage using the GPD TEE Internal Core API.
* Test application: `optee_example_secure_storage`
* Benchmarking: create, read and delete a 7000 B object (C char []) from Secure and Non Secure Memory

**Operation (100 Runs)** | **S `avg(ms)`** | **S `stdev(ms^2)`** | **NS `avg(ms)`** | **NS `stdev(ms^2)`**
----- | :-----: | :-----: | :-----: | :-----:
**`create`** | 70.502480 | 5.221423 | 0.004120 | 0.012384
**`read`** | 34.511310 | 3.197807 | 0.094970 | 0.043544
**`delete`** | 49.678530 | 4.697380 | 0.007390 | 0.008262
---
## 3. Run the example applications
The current applciations and results are executed using QEMUv8. For instructions on how to build the distribution go [here](https://optee.readthedocs.io/building/devices/qemu.html#qemu-v8).

Once you have the distribution installed and compiled, go to you project source (`optee-qemuv8` most likely) and replace the existing `optee_examples` with this repository. Then, assuming you are in the project source directory,
```
cd build
make -j `nproc`
make run
```

Ideally, two terminal windows should pop up, first go to the build repo and pres `c`, then from the *Normal* terminal window, type in `test` as login and then `cd /usr/bin`. There you will find all the example applications to be run.
