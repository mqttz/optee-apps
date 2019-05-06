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

