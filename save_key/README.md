### Save Key Trusted Application

Store a `<cli_id, cli_key>` pair in Secure Storage. It supports both sending the `cli_key` sotred with the TZ-specific private key or in plain text.

The TA takes three parameters through the command line:
    + `cli_id`: the client ID in the MQTTZ format.
    + `mode`: 1 for encrypted, 0 for plain (**use 0 only for testing purposes**)
    + `cli_key`: key to be stored.
