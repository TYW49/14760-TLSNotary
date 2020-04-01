# 14760-TLSNotary

We mainly focus on implementing an additional protection mechanism above the Transport Layer Security (TLS) protocol to ensure the users to retrieve secure data from the network transfers. For getting data from web servers, this can be done in two ways, from the server side and the client side. The server side would require the modi?cation of the TLS protocol and a third party auditor can be used in the client side to attest a TLS connection. Our work allows a client to provide evidence to a third party auditor that certain web tra?c occurred between himself and a server. 

In this project, we will implement the algorithms, change the client side into two parts: Auditor and Auditee, deploy the Auditor, run the Auditee side to generate veri?cation, and ?nally ?nd ways to improve the performance of the system. Furthermore, we also want to ?nd more application scenarios for the additional protection mechanism. For example, how to deploy them on top of IoT data infrastructure, which requires credible real-world data acquired from the sensors. At last, we decide to conduct three experiments on function, latency and security. 

Now, we have finished deploying Auditor on AWS and complete the code of Auditee. The system can successfully run. Here are two pictures to describe the process of the system. 

![notarize process](http://github.com/TYW49/14760-TLSNotary/raw/master/img/notarize.jpg)
![review process](http://github.com/TYW49/14760-TLSNotary/raw/master/img/nreview file.jpg)

**Steps**

1. Import reliable sites. During the process of building TLS link，Auditee is responsible for transferring product of the two pre-master secret, which encrypted in RSA, to server during time of second handshake. The property of RSA multiplicative homomorphismis is applied here. To satisfy the 2048bit encryption specification in RSA [RFC 2313]，a padding sequence need to be generated，and the padding sequence cannot contain 0 byte . Therefore, before the connection to the server succeeds, it is necessary to obtain reliable sites in advance for verification purpose. If the padding sequence contains 0 byte, a new padding sequence will be generated. Hence, the imported reliable sites list in the Auditor could be used for future verification.
2. Build up socket communication in threads. Because multiple users could get access to Auditee in parallel, interacting with Auditor.
3. Auditor keeps the state of listen up for incoming request after running.
4. Handle  every connection request after receiving it. And process them based on the content of requests. Finally, response is generated and sent to Auditee.

