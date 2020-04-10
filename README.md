﻿# 14760-TLSNotary

We mainly focus on implementing an additional protection mechanism above the Transport Layer Security (TLS) protocol to ensure the users to retrieve secure data from the network transfers. For getting data from web servers, this can be done in two ways, from the server side and the client side. The server side would require the modification of the TLS protocol and a third party auditor can be used in the client side to attest a TLS connection. Our work allows a client to provide evidence to a third party auditor that certain web trafic occurred between himself and a server. 

In this project, we will implement the algorithms, change the client side into two parts: Auditor and Auditee, deploy the Auditor, run the Auditee side to generate verification, and fnally find ways to improve the performance of the system. Furthermore, we also want to find more application scenarios for the additional protection mechanism. For example, how to deploy them on top of IoT data infrastructure, which requires credible real-world data acquired from the sensors. At last, we decide to conduct three experiments on function, latency and security. 

Now, we have finished deploying Auditor on AWS and complete the code of Auditee. The system can successfully run. Here are two pictures to describe the process of the system. 

![image](https://github.com/TYW49/14760-TLSNotary/blob/master/img/notarize.jpg)
![image](https://github.com/TYW49/14760-TLSNotary/blob/master/img/review.jpg)



