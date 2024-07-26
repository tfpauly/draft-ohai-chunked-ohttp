---
title: "Chunked Oblivious HTTP Messages"
abbrev: "Chunked OHTTP"
category: std

docname: draft-ietf-ohai-chunked-ohttp-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: ART
workgroup: OHAI Working Group
venue:
  group: OHAI
  type: Working Group
  mail: ohai@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/ohai/
  github: ietf-wg-ohai/draft-ohai-chunked-ohttp
  latest: https://ietf-wg-ohai.github.io/draft-ohai-chunked-ohttp/draft-ietf-ohai-chunked-ohttp.html

author:
 -
    fullname: Tommy Pauly
    organization: Apple
    email: tpauly@apple.com
 -
    fullname: Martin Thomson
    organization: Mozilla
    email: mt@lowentropy.net

--- abstract

This document defines a variant of the Oblivious HTTP message format that allows
chunks of requests and responses to be encrypted and decrypted before the entire
request or response is processed. This allows incremental processing of Oblivious
HTTP messages, which is particularly useful for handling large messages or systems
that process messages slowly.

--- middle

# Introduction

Oblivious HTTP {{!OHTTP=I-D.ietf-ohai-ohttp}} defines a system for sending HTTP requests
and responses as encrypted messages. Clients send requests via a relay to a gateway, which
is able to decrypt and forward the request to a target server. Responses are encrypted
with an ephemeral symmetric key by the gateway and sent back to the client via the relay.
The messages are protected with Hybrid Public Key Encryption (HPKE; {{!HPKE=RFC9180}}),
and are intended to prevent the gateway from linking any two independent requests to the
same client.

The definition of Oblivious HTTP in {{OHTTP}} encrypts messages such that entire request
and response bodies need to be received before any of the content can be decrypted. This
is well-suited for many of the use cases of Oblivious HTTP, such as DNS queries or metrics
reporting.

However, some applications of Oblivious HTTP can benefit from being able to encrypt and
decrypt parts of the messages in chunks. If a request or response can be processed by a
receiver in separate parts, and is particularly large or will be generated slowly, then
sending a series of encrypted chunks can improve the performance of applications.

Incremental delivery of responses allows an Oblivious Gateway Resource to provide
Informational (1xx) responses ({{Section 15.2 of ?HTTP=RFC9110}}).

This document defines an optional message format for Oblivious HTTP that supports the
progressive creation and processing of both requests and responses. New media types are
defined for this purpose.

## Applicability

Like the non-chunked variant, chunked Oblivious HTTP has limited applicability
as described in {{Section 2.1 of OHTTP}}, and requires the use of a willing
Oblivious Relay Resource and Oblivious Gateway Resource.

Chunked Oblivious HTTP is intended to be used in cases for where the privacy
properties of Oblivious HTTP are needed — specifically, removing linkage
at the transport layer between separate HTTP requests — but incremental
processing is also needed for performance or functionality.

One specific functional capability that requires chunked Oblivious HTTP
is support for Informational (1xx) responses
({{Section 15.2 of ?HTTP=RFC9110}}).

In order to be useful, the content of chunked Oblivious HTTP needs to be
possible to process incrementally. Since incremental processing means that the
message might end up being truncated, for example in the case of an error on the
underlying transport, applications also need to be prepared to safely handle incomplete
messages (see {{security}} for more discussion). Applications that use the Indeterminate
format of Binary HTTP ({{Section 3.2 of !BHTTP=RFC9292}}) are well-suited
to using chunked Oblivious HTTP.

Chunked Oblivious HTTP is not intended to be used for long-lived sessions
between clients and servers that might build up state, or as a replacement
for a proxied TLS session.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Notational conventions from {{OHTTP}} are used in this document.

# Chunked Request and Response Media Types

Chunked Oblivious HTTP defines different media than the non-chunked variant. These
media types are "message/ohttp-chunked-req" (defined in {{iana-req}}) and
"message/ohttp-chunked-res" (defined in {{iana-res}}).

# Request Format {#request}

Chunked OHTTP requests start with the same header as used for the non-chunked variant,
which consists of a key ID, algorithm IDs, and the KEM shared secret. This header is
followed by chunks of data protected with HPKE, each of which is preceded by a
variable-length integer (as defined in {{Section 16 of !QUIC=RFC9000}})
that indicates the length of the chunk. The final chunk is preceded by a length
field with the value 0, which means the chunk extends to the end of the outer stream.

~~~
Chunked Encapsulated Request {
  Chunked Request Header (56 + 8 * Nenc),
  Chunked Request Chunks (..),
}

Chunked Request Header {
  Key Identifier (8),
  HPKE KEM ID (16),
  HPKE KDF ID (16),
  HPKE AEAD ID (16),
  Encapsulated KEM Shared Secret (8 * Nenc),
}

Chunked Request Chunks {
  Non-Final Request Chunk (..),
  Final Request Chunk Indicator (i) = 0,
  HPKE-Protected Final Chunk (..),
}

Non-Final Request Chunk {
  Length (i) = 1..,
  HPKE-Protected Chunk (..),
}
~~~
{: #fig-enc-request title="Chunked Encapsulated Request Format"}

The content of the HPKE-protected chunks is defined in {{request-encap}}.

# Response Format {#response}

Chunked OHTTP responses start with a nonce, followed by chunks of data protected with
an AEAD. Each chunk is preceded by a variable-length integer that indicates the length
of the chunk. The final chunk is preceded by a length field with the value 0, which means
the chunk extends to the end of the outer stream.

~~~
Chunked Encapsulated Response {
  Response Nonce (Nk),
  Chunked Response Chunks (..),
}

Chunked Response Chunks {
  Non-Final Response Chunk (..),
  Final Response Chunk Indicator (i) = 0,
  AEAD-Protected Final Response Chunk (..),
}

Non-Final Response Chunk {
  Length (i) = 1..,
  AEAD-Protected Chunk (..),
}
~~~
{: #fig-enc-response title="Chunked Encapsulated Response Format"}

# Encapsulation of Chunks

The encapsulation of chunked Oblivious HTTP requests and responses uses
the same approach as the non-chunked variant, with the difference that
the body of requests and responses are sealed and opened in chunks, instead
of as a whole.

The AEAD that protects both requests and responses protects individual chunks from
modification or truncation. Additionally, chunk authentication protects two other
pieces of information:

1. the order of the chunks (the sequence number of each chunk), which is
included in the nonce of each chunk.
1. which chunk is the final chunk, which is indicated by a sentinel in the AAD
of the final chunk.

The format of the outer packaging that carries the chunks (the length prefix for each
chunk specifically) is not explicitly authenticated. This allows the chunks to be
transported by alternative means, and still be valid as long as the order and
finality are preserved.  In particular, the variable-length encoding used for lengths
allows for different expressions of the same value, where the choice between
equivalent encodings is not authenticated.

## Request Encapsulation {#request-encap}

For requests, the setup of the HPKE context and the encrypted request header
is the same as the non-chunked variant. This is the Chunked Request Header
defined in {{request}}.

~~~
hdr = concat(encode(1, key_id),
             encode(2, kem_id),
             encode(2, kdf_id),
             encode(2, aead_id))
info = concat(encode_str("message/bhttp chunked request"),
              encode(1, 0),
              hdr)
enc, sctxt = SetupBaseS(pkR, info)
enc_request_hdr = concat(hdr, enc)
~~~

Each chunk is sealed using the HPKE context. For non-final chunks, the AAD
is empty.

~~~
sealed_chunk = sctxt.Seal("", chunk)
sealed_chunk_len = varint_encode(len(sealed_chunk))
non_final_chunk = concat(sealed_chunk_len, sealed_chunk)
~~~

The final chunk in a request uses an AAD of the string "final".

~~~
sealed_final_chunk = sctxt.Seal("final", chunk)
sealed_final_chunk_len = varint_encode(len(sealed_final_chunk))
final_chunk = concat(sealed_final_chunk_len, sealed_final_chunk)
~~~

HPKE already maintains a sequence number for sealing operations as part of
the context, so the order of chunks is protected. HPKE will produce an
error if the sequence number overflows, which puts a limit on the number
of chunks that can be sent in a request.

## Response Encapsulation {#response-encap}

For responses, the first piece of data sent back is the response nonce,
as in the non-chunked variant. As in the non-chunked variant, the length
of the nonce is `max(Nn, Nk)`, where `Nn` and `Nk` are the length of
the AEAD nonce and key.

~~~
entropy_len = max(Nn, Nk)
response_nonce = random(entropy_len)
~~~

Each chunk is sealed using the same AEAD key and AEAD nonce that are
derived for the non-chunked variant, which are calculated as follows:

~~~
secret = context.Export("message/bhttp chunked response", entropy_len)
salt = concat(enc, response_nonce)
prk = Extract(salt, secret)
aead_key = Expand(prk, "key", Nk)
aead_nonce = Expand(prk, "nonce", Nn)
~~~

The sender also maintains a counter of chunks, which is set to 0 for the first
chunk an incremented by 1 after encoding each chunk.

~~~
counter = 0
~~~

The AEAD nonce is XORed with the counter for encrypting (and decrypting) each
chunk.  For non-final chunks, the AAD is empty.

~~~
chunk_nonce = aead_nonce XOR encode(Nn, counter)
sealed_chunk = Seal(aead_key, chunk_nonce, "", chunk)
sealed_chunk_len = varint_encode(len(sealed_chunk))
non_final_chunk = concat(sealed_chunk_len, sealed_chunk)
counter++
~~~

The final chunk in a response uses an AAD of the string "final".

~~~
chunk_nonce = aead_nonce XOR encode(Nn, counter)
sealed_final_chunk = Seal(aead_key, chunk_nonce, "final", chunk)
sealed_final_chunk_len = varint_encode(len(sealed_final_chunk))
final_chunk = concat(sealed_final_chunk_len, sealed_final_chunk)
~~~

If the counter reached the maximum value that can be held in an
integer with `Nn` bits (that maximum being `2^Nn`), where `Nn` is the
length of the AEAD nonce, the `chunk_nonce` would wrap and be reused.
Therefore, the response MUST NOT use `2^Nn` or more chunks.

# Security Considerations {#security}

The primary advantage of a chunked encoding is that chunked requests or responses can
be generated or processed incrementally.  However, for a recipient in particular,
processing an incomplete message can have security consequences.

The potential for message truncation is not a new concern for HTTP.  All versions of
HTTP provide incremental delivery of messages.  For this use of Oblivious HTTP,
incremental processing that might result in side-effects demands particular attention
as Oblivious HTTP does not provide strong protection against replay attacks; see
{{Section 6.5 of OHTTP}}.  Truncation might be the result of interference at the
network layer, or by a malicious Oblivious Relay Resource.

Endpoints that receive chunked messages can perform early processing if the risks are
understood and accepted. Conversely, endpoints that depend on having a complete
message MUST ensure that they do not consider a message complete until having
received a chunk with a 0-valued length prefix, which was successfully decrypted
using the expected sentinel value, "final", in the AAD.

## Interactivity and Privacy

Without chunking, Oblivious HTTP involves a single request and response, with no
further interactivity.  Using a chunked variant at both Client and Oblivious
Gateway Resource creates the possibility that an exchange could lead to multiple
rounds of interaction.  Information from early chunks from a peer could
influence how an endpoint constructs later chunks of their message.

An Oblivious Gateway Resource could be able to observe the round trip time to
the Client if the Client conditions the timing or content of chunks on what it
receives in a response.

Client implementations therefore need to be aware of the possibility that
processing chunks might result in observable interactivity that could reduces
the privacy protection that the protocol could otherwise provide.  Interactivity
that is deliberate might be acceptable. For instance, the 100-continue feature
in HTTP, which has the client withhold the body of a request until it receives a
100 Informational response, is not possible without chunked encoding.  This
highlights the risks involved in the use of this chunked encoding to adapt an
existing HTTP-based interaction to use Oblivious HTTP as such an adaptation
might not achieve expected privacy outcomes.
In order to prevent the Oblivious Gateway Resource from observing the round trip time
to the client, client implementations can choose to not base the sending of request chunks based
on received response chunks. These interactions can still benefit from chunked processing,
without incurring additional observability risks.

# IANA Considerations

This document updates the "Media Types" registry at
<https://iana.org/assignments/media-types> to add the media types
"message/ohttp-chunked-req" ({{iana-req}}), and
"message/ohttp-chunked-res" ({{iana-res}}), following the procedures of
{{!RFC6838}}.

## message/ohttp-chunked-req Media Type {#iana-req}

The "message/ohttp-chunked-req" identifies an encrypted binary HTTP request
that is transmitted or processed in chunks. This is a binary format that is
defined in {{request}}.

Type name:

: message

Subtype name:

: ohttp-chunked-req

Required parameters:

: N/A

Optional parameters:

: N/A

Encoding considerations:

: "binary"

Security considerations:

: see {{security}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: Oblivious HTTP and applications that use Oblivious HTTP use this media type to
  identify encapsulated binary HTTP requests that are incrementally generated or processed.

Fragment identifier considerations:

: N/A

Additional information:

: <dl spacing="compact">
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IETF
{: spacing="compact"}


## message/ohttp-chunked-res Media Type {#iana-res}

The "message/ohttp-chunked-res" identifies an encrypted binary HTTP response
that is transmitted or processed in chunks. This is a binary format that
is defined in {{response}}.

Type name:

: message

Subtype name:

: ohttp-chunked-res

Required parameters:

: N/A

Optional parameters:

: N/A

Encoding considerations:

: "binary"

Security considerations:

: see {{security}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: Oblivious HTTP and applications that use Oblivious HTTP use this media type to
  identify encapsulated binary HTTP responses that are incrementally generated or processed.

Fragment identifier considerations:

: N/A

Additional information:

: <dl spacing="compact">
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IETF
{: spacing="compact"}

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledgements.
