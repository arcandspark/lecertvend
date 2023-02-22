# Certificate Vending Machine

lecertvend issues or renews single certificates, or groups of certificates,
and stores them and their associated keys in Vault. The authorization to issue
certificates for a particular domain is determined by the Vault token's 
ability to access the specified storage prefix in the Vault, and the 
presence of a CloudFlare token in that location which can be used for 
solving DNS challenges.

Vault Secrets Structure:
The -prefix must consist of a path that contains at least one
parent folder, and a folder for the domain for which certificates
will be issued.

The parent folder must contain a secret called "cftoken" with
a key named "token". This will be used as the CloudFlare API
token for solving DNS challenges.

This structure helps facilitate Vault policies which offer
access to issue and renew certs for a subset of the domains
stored in the Vault and managed by lecertvend.

The secrets containing certificates and keys will have a
key named `cert` and a key named `key`. These are the FULL CERT CHAIN
and the private key respectively. The value will be PEM encoded cert/key 
data.

```
Example structure:
    /lecertmgmt
        /example
            cftoken
            /example.com
                www = { cert: PEM, key: PEM }
                login
        /someorg
            cftoken
            /somesite.biz
                bare
            /anotherdomain.info
                www
                mail
```