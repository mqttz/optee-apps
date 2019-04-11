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

