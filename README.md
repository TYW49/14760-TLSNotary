# 14760-TLSNotary

Although TLS protocol is already used to encrypt network data for other network protocols such as HTTP protocol, there still exists attacks aiming at SSL/TLS such as man-in-the-middle attack. The attacker would establish separate connections with the server and client, disguise as a legal connection endpoint, and intercept normal network data to alter or insert illegal data without being recognized. Users are currently unable to prove to a third party the content they have observed on a particular website. One of the most popular methods for users to document and share content they watch on the Internet are screenshots that are trivial to falsify, which is inefficient and inconvenient. However, TLSNotary allows a client to provide evidence to a third-party auditor that certain web traffic occurred between himself and a server. The evidence is irrefutable as long as the auditor trusts the server’s public key. Apart from web scenarios, TLSNotary can also be applied to the blockchain, physical sensors and so on to provide reliable real data. 

We mainly focus on implementing an additional protection mechanism above the Transport Layer Security (TLS) protocol to ensure users to retrieve secure data from the network transfers. For example, for getting data from web servers, this can be done in two ways, from the server side and the client side. The server side would require the modification of the TLS protocol and a third party auditor can be used in the client side to attest a TLS connection. We will study the nature of the network between the server and the client, some detailed descriptions of TLS and HTTP and utilize some properties of the cryptography algorithms to achieve our desired results. After that, we will implement the algorithms, deploy the server and the client side to generate verification between different servers, and finally find ways to improve the performance of the algorithms. 

We finished coding the TLSNotary system and deploying Auditor on AWS, also we developed a web application to run the system. After that, we conducted 3 experiments on functional, latency and security. 


![image](https://github.com/TYW49/14760-TLSNotary/blob/master/project%20implementation/img/notarize.jpg)
![image](https://github.com/TYW49/14760-TLSNotary/blob/master/project%20implementation/img/review.jpg)


