
**Steps**

1. Import reliable sites. During the process of building TLS link£¬Auditee is responsible for transferring product of the two pre-master secret, which encrypted in RSA, to server during time of second handshake. The property of RSA multiplicative homomorphismis is applied here. To satisfy the 2048bit encryption specification in RSA [RFC 2313]£¬a padding sequence need to be generated£¬and the padding sequence cannot contain 0 byte . Therefore, before the connection to the server succeeds, it is necessary to obtain reliable sites in advance for verification purpose. If the padding sequence contains 0 byte, a new padding sequence will be generated. Hence, the imported reliable sites list in the Auditor could be used for future verification.
2. Build up socket communication in threads. Because multiple users could get access to Auditee in parallel, interacting with Auditor.
3. Auditor keeps the state of listen up for incoming request after running.
4. Handle  every connection request after receiving it. And process them based on the content of requests. Finally, response is generated and sent to Auditee.
