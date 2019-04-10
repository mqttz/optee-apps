# OP-TEE Benchmarking Algorithms & Building Blocks of MQTT-TZ
## Contents
1. [Introduction](#1-introduction)
2. [List of sample applications](#2-list-of-sample-applications)
3. [How to build a Trusted Application](#3-how-to-build-a-trusted-application)


## 1. Introduction
This document describes the different benchmarking applciations developed with the Op-TEE framework together with the implemented min-apps that will pave the way for the MQTT-TZ implementation.

---
## 2. List of sample applications

Directory **hello_world/**:
* A very simple Trusted Application to answer a hello command and incrementing
an integer value.
* Test application: `optee_example_hello_world`

Directory **aes/**:
* Runs an AES encryption and decryption from a TA using the GPD TEE Internal
Core API. Non secure test application provides the key, initial vector and
ciphered data.
* Test application: `optee_example_aes`
* Benchmarking: secure vs non secure encryption and decryption. 100 times, report avg and std:

Directory **secure_storage/**:
* A Trusted Application to read/write raw data into the
OP-TEE secure storage using the GPD TEE Internal Core API.
* Test application: `optee_example_secure_storage`
* Benchmarking: 

<> Directory **acipher/**:
<> * Generates an RSA key pair of specified size and encrypts a supplied string
<>  with it using the GPD TEE Internal Core API.
<> * Test application: `optee_example_acipher`
<> * Trusted application UUID: a734eed9-d6a1-4244-aa50-7c99719e7b7b

## 3. How to build a Trusted Application
[TA basics] documentation presents the basics for  implementing and building
an OP-TEE trusted application.

One can also refer to the examples provided: source files and make scripts.

[TA basics]:	./docs/TA_basics.md
