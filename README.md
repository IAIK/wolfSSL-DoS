CVE-2015-6925 [1, 2]: DoS attack on wolfSSL DTLS server and DoS amplification
=============================================================================

DTLS 1.2 [5] includes an optional extra round trip based on a cookie in the
handshake phase to prevent the following two attack scenarios:

 1. DoS of the DTLS server caused by forcing the server to allocate an extensive
    amount of resources or by performing expensive computations, and

 2. amplifying a DoS attack via a forged source.

The implementation of the protection is roughly:

 1. The ClientHello message is extended to include a cookie. If the client does
    not posses a cookie, it sends a zero length cookie.

 2. The server checks while receiving a ClientHello whether the message contains
    a valid cookie. If the cookie is valid, the server proceeds with the normal
    handshake. If the cookie is invalid, it replies with a HelloVerifySent
    including a cookie for this client.

 3. If a client receives a HelloVerifySent after a ClientHello message, it
    includes the received cookie in the ClientHello message and resends it.

Attack scenario 2. can easily be prevented by generating random cookies on the
server and storing them. But this does not help with attack scenario 1. as it
would require to store the computed cookies. So the cookie is implemented
stateless and the recommendation in the RFC is to use an HMAC and computing the
cookie like

```
  HMAC(client address || constant data from the ClientInfo message)
```

where the HMAC key is global state on the server and not per session state. This
allows the cookie to be regenerated only be looking at the ClientInfo message
and the sender.

The DTLS server implementation included in wolfSSL implements this cookie based
approach, but uses an hash function instead of a keyed function like an HMAC.
But then the cookie does not contain any secret data and valid cookies can be
computed by an adversary, making the DTLS server vulnerable to attack scenarios
1. and 2.

Timeline
--------

 * 2015-09-11: wolfSSL has been informed about this issue and were provided with
               the proof of concept code to reproduce it.
 * 2015-09-18: wolfSSL 3.6.8 including a fix for this issue has been released
               [4].
 * 2015-09-23: Publication of the PoC.

Proof of concept
----------------

This is a simple example demonstrating CVE-2015-6925. It sends
ClientHello messages with spoofed sender addresses but valid cookies to a
wolfSSL based DTLS server. All wolfSSL versions supporting DTLS before 3.6.8 are
affected by this vulnerability.

 * attack.c: Sends the spoofed ClientHello messages.
 * dtls-server.c: Very simple DTLS server (slightly modified version of [3])
 * target.c: Listens and prints the number of bytes received.

Assume the following scenario:

 * dtls-server runs on a machine with IP 192.168.0.1.
 * target runs on a machine with IP 192.168.0.2.
 * attack runs on any other machine.

Now run

```bash
  $ attack -i $interface --server 192.168.0.1 --target 192.168.0.2
```

where $interface is the network interface the packets should be sent on. If
there is a gateway involved or attack can not detect the MAC address of the
server, specify --server-hwaddr.

attack needs superuser privileges to run.

target should print

```
  Received 48 bytes. (for the HelloVerifyRequest message)
```

and about seven times (based on the default timeouts)

```
  Received 95 bytes. (for the ServerHello message)
  Received 3281 bytes. (for the Certificate message)
  Received 482 bytes. (for the ServerKeyExchange message)
  Received 25 bytes. (for the ServerHelloDone message)
```

The numbers depend on the choice of algorithms and may vary with the choice of
algorithms and packet fragmentation of the handshake packets.

Reference
---------

[1] https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-6925
[2] https://www.wolfssl.com/wolfSSL/Blog/Entries/2015/9/17_Two_Vulnerabilities_Recently_Found,_An_Attack_on_RSA_using_CRT_and_DoS_Vulnerability_With_DTLS.html
[3] https://github.com/wolfSSL/wolfssl-examples/blob/master/dtls/server-dtls.c
[4] http://wolfssl.com/wolfSSL/Blog/Entries/2015/9/18_wolfSSL_3.6.8_is_Now_Available.html
[5] https://tools.ietf.org/html/rfc6347
