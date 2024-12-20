# Java Callout for WS-Security Digital Signature

This repo contains the Java source code and pom.xml file required to compile a
simple Java callout for Apigee, that creates or validates a _signed_ SOAP
document that complies with [the SOAP Message Security standard](https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SOAPMessageSecurity-v1.1.1-os.html), sometimes referred to as WS-Security. This repo also contains
the packaged jar.

There's a great deal of flexibility in the WS-Security standard, in terms of how
signatures are generated and embedded into a document, and how keys are
referenced. This callout in particular supports:

- RSA key pairs
- Signing or validating with RSA-SHA1 (http://www.w3.org/2000/09/xmldsig#rsa-sha1 ) or RSA-SHA256 (http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 ). The latter is highly recommended.
- using a digest method of sha1 (http://www.w3.org/2000/09/xmldsig#sha1) or sha256 (http://www.w3.org/2001/04/xmlenc#sha256) . The latter is highly recommended.

- When signing
  - signing either or both of the soap:Body, and the wssec:Security/wsu:Timestamp element, and optionally signing SignatureConfirmation elements. Signing both Body and Timestamp is highly recommended.
  - injecting a Timestamp element if one does not exist, with an expiry, optionally
  - injecting one or more SignatureConfirmation elements as necessary

- When validating
  - checking that the WS-Security Security header is a child of the SOAP Header
  - validating all signatures
  - checking that either the Body, or the Timestamp, or both, have been signed.
  - checking the Timestamp expiry, and optionally the maximum lifetime of the signed document
  - checking signatures via public keys embedded in X509v3 certificates.
  - Obtaining the certificates to use to Validate in one of two ways: either in the signed document itself, or as configuration to the Validate step.



## Status

This _replaces_ the previous version of the callout, which can still be found at
[this link](https://github.com/DinoChiesa/ApigeeEdge-Java-WsSec-Signature) .
The previous version of the callout was not parameterizable, and also depended
upon wss4j. The wss4j dependency prevented the use of the callout in Apigee Edge
or Apigee X (cloud hosted versions of Apigee). This callout does not have a
dependency on wss4j, and can run in the cloud-hosted versions of Apigee.  Also,
this callout is much more flexible and parameterizable.


## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## License

This material is [Copyright 2018-2024, Google LLC.](./NOTICE)
and is licensed under the Apache 2.0 license. See the [LICENSE](LICENSE) file.

This code is open source but you don't need to compile it in order to use it.

## Building

You do not need to build this callout in order to use it. You can build it if
you wish. To do so, use [Apache Maven](https://maven.apache.org/). To build, you need:

- JDK 8 or JDK 11
- maven v3.9 at a minimum

To build on JDK 11, make sure you have a JDK11 bin on your path, and:

```
mvn clean package
```

To build on JDK 8, make sure you have a JDK8 bin on your path, and:

```
mvn -f pom-java8.xml clean package
```

The 'package' goal will copy the jar to the resources/java directory for the
example proxy bundle. If you want to use this in your own API Proxy, you need
to copy this JAR into the appropriate API Proxy bundle. Or include the jar as an
environment-wide or organization-wide jar via the Apigee administrative API.


## Details

There is a single jar, apigee-wssecdsig-20241129.jar . Within that jar, there are two callout classes,

* com.google.apigee.callouts.wssecdsig.Sign - signs the input SOAP document.
* com.google.apigee.callouts.wssecdsig.Validate - validates the signed SOAP document

The Sign callout has these constraints and features:
* supports RSA algorithms - rsa-sha1 (default) or rsa-sha256
* supports soap1.1 and soap1.2
* Will automatically add a Timestamp to the WS-Security header
* Can optionally add an explicit Expiry to that timestamp (recommended)
* signs the SOAP Body, or the Timestamp, or both (default)
* uses a canonicalization method of "http://www.w3.org/2001/10/xml-exc-c14n#"
* uses a digest mode of sha1 (default) or sha256
* has various options for embedding the KeyInfo for the certificate in the signed document: directly embedding the certificate, embedding a thumprint, a serial number, or embedding a public RSA key.

The Validate callout has these constraints and features:
* supports RSA algorithms - rsa-sha1 (default) or rsa-sha256 (recommended)
* supports soap1.1. (Not tested with soap 1.2; might work!)
* Enforces the location of the WS-Sec Security element as a child of the SOAP header (by default, though this is optional.
* If a Timestamp is present in the WS-Security header, validates expiry.
* Optionally _require_ that a Timestamp is present in the WS-Security header, with an Expires element.
* Optionally enforce a maximum lifetime of the signature. This is the difference between Created and Expires within the Timestamp. You may wish to limit this to 5 minutes, for example.
* verify that a specific digest method - sha-1 or sha-256 - is used when signing.
* verify that the certificate that provides the verification key, is not expired
* verify the thumbprint on the certificate that provides the verification key
* optionally verify the Common Name on the certificate matches a particular value

## Dependencies

Make sure these JARs are available as resources in the  proxy or in the environment or organization.

* Bouncy Castle: bcprov-jdk15on-1.66.jar, bcpkix-jdk15on-1.66.jar

This Callout does not depend on WSS4J.  The WSS4J is prohibited from use within
Apigee SaaS, due to Java permissions settings. This callout is intended to be
usable in Apigee SaaS (Edge or X), OPDK, or hybrid.

## Usage

### Signing

Configure the policy this way:

```xml
<JavaCallout name='Java-WSSEC-Sign'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='output-variable'>output</Property>
    <Property name='expiry'>180s</Property>
    <Property name='signing-method'>rsa-sha256</Property>
    <Property name='digest-method'>sha256</Property>
    <Property name='private-key'>{my_private_key}</Property>
    <Property name='certificate'>{my_certificate}</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.wssecdsig.Sign</ClassName>
  <ResourceURL>java://apigee-wssecdsig-20241129.jar</ResourceURL>
</JavaCallout>
```

There are a number of available properties for configuring the Sign callout, to
affect the shape of the signed document. This affects things like what elements
to sign, which signature method to use, the desired format of the Key
Information, and much more. These properties are described in detail here:

| name                 | description |
| -------------------- | ------------ |
| `source`               | optional. the variable name in which to obtain the source document to sign. Defaults to message.content |
| `soap-version`         | optional. Either `soap1.1` or `soap1.2`. Defaults to `soap1.1` . |
| `output-variable`      | optional. the variable name in which to write the signed XML. Defaults to `message.content` |
| `private-key`          | required. the PEM-encoded RSA private key. You can use a variable reference here as shown above. Probably you want to read this from a secure store - maybe the encrypted KVM. |
| `private-key-password` | optional. The password for the key, if it is encrypted. |
| `key-identifier-type`  | optional. One of {`BST_DIRECT_REFERENCE`, `THUMBPRINT`,  `ISSUER_SERIAL`, `X509_CERT_DIRECT`, or `RSA_KEY_VALUE`}.  Defaults to `BST_DIRECT_REFERENCE`. See below for details on these options. |
| `issuer-name-style`    | optional. One of {`CN`, `DN`}.  This is relevant only if `key-identifier-type` has the value `ISSUER_SERIAL`. See below for details. |
| `certificate`          | required. The certificate matching the private key. In PEM form. |
| `signing-method`       | optional. Takes value `rsa-sha1` or `rsa-sha256`. Defaults to `rsa-sha1`. Despite this, `rsa-sha256` is highly recommended. |
| `digest-method`        | optional. Takes value `sha1` or `sha256`. Defaults to `sha1`. If you have the flexibility to do so, it's preferred that you use `sha256`. |
| `elements-to-sign`     | optional. Takes a comma-and-maybe-space-separated value of prefix:Tag forms. For example "wsu:Timestamp, soap:Body, wsa:To, wsa:MessageID".  Case is important. Default: the signer signs both the wsu:Timestamp and the soap:Body. |
| `expiry`               | optional. Takes a string like 120s, 10m, 4d, etc to imply 120 seconds, 10 minutes, 4 days, and injects an Expires element into the Timestamp. Default: no expiry. |
| `c14-inclusive-elements` | optional. Takes a comma-separated value of namespace _URIs_ (not prefixes). Used to add an InclusiveElements element to the CanonicalizationMethod element.  |
| `transform-inclusive-elements` | optional. Takes a comma-separated value of namespace _URIs_ (not prefixes). Used to add an InclusiveElements element to the Transform element.  |
| `ds-prefix`            | optional. A simple string, to be used as the prefix for the namespace "http://www.w3.org/2000/09/xmldsig#". Some users have expressed a desire to control this, and this callout makes it possible. This property affects the aesthetics of the document only, does not affect the XML InfoSet. In case you care, the default prefix is "ds".  |
| `confirmations`        | optional. Either: (a) a list of signature values in SignatureConfirmation elements, which will then be signed. If a SignatureConfirmation element with a given value is not present, one will be injected. or (b) the string `\*all\*` , to indicate that any existing SignatureConfirmation elements in the source document will be signed. or (c) an empty string, which tells the callout to inject an empty SignatureConfirmation element. These signatures are in addition to the elements specified in `elements-to-sign`. |
| `ignore-security-header-placement` | optional. true or false, defaults false. When true, tells the sign callout to not check the placement of any existing Security header in the unsigned payload. For compatibility with some legacy systems. This is not recommended because it can expose you to [signature wrapping attacks](https://secops.group/xml-signature-wrapping/). |


This policy will create the appropriate signature or signatures, and embed each
Signature element as a child of the WS-Security header element.

The value you specify for the `key-identifier-type` property affects the shape of the output `KeyInfo` element.  These are the options:

* `bst_direct_reference`. This is the default; this is what you get if you omit
  this property. With this setting, the Sign callout embeds the certificate into
  the signed document using a `BinarySecurityToken` and a `SecurityTokenReference`
  that points to it.

  The resulting `KeyInfo` element looks like this:
  ```xml
   <KeyInfo>
     <wssec:SecurityTokenReference>
       <wssec:Reference URI="#SecurityToken-e828bfab-bb52-4429"
           ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
     </wssec:SecurityTokenReference>
   </KeyInfo>
  ```

  And there will be a child element of the `wssec:Security` element that looks like
  this:
  ```xml
      <wssec:BinarySecurityToken
          EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
          ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
          wsu:Id="SecurityToken-e828bfab-bb52-4429-b6a4-755b26abc387">MIIC0...</wssec:BinarySecurityToken>
  ```

* `thumbprint` gives you a `SecurityTokenReference` with a `KeyIdentifier`, like this:

  ```xml
   <KeyInfo>
     <wsse:SecurityTokenReference>
       <wsse:KeyIdentifier
             ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security1.1#ThumbprintSHA1">9JscCwWHk5IvR/6JLTSayTY7M=</wsse:KeyIdentifier>
     </wsse:SecurityTokenReference>
   </KeyInfo>
  ```
  Use this if you plan to share the certificate with the receiver, and the receiver will
  verify the certificate via  the thumbprint.  There is no way to embed a SHA256 thumbprint of the certificate, today.


* `issuer_serial` (common with WCF) gives you a `SecurityTokenReference` with an identification of an X509 cert, like this:

  ```xml
   <KeyInfo>
     <wsse:SecurityTokenReference wsu:Id="STR-2795B41DA34FD80A771574109162615125">
       <X509Data>
         <X509IssuerSerial>
           <X509IssuerName>CN=common.name.on.cert</X509IssuerName>
           <X509SerialNumber>837113432321</X509SerialNumber>
         </X509IssuerSerial>
       </X509Data>
     </wsse:SecurityTokenReference>
   </KeyInfo>
  ```

  For this case, you can optionally specify another property,
  `issuer-name-style`, as either `CN` or `DN`.  For the former, and an example
  for that is shown above; only the CN is included in the `IssuerName`
  element. The latter is the default, and provides the full distinguished name (DN),
  which results in something like this:

   ```xml
   <X509IssuerSerial>
     <X509IssuerName>C=US,ST=Washington,L=Kirkland,O=Google,OU=Apigee,CN=apigee.google.com,E=dino@apigee.com</X509IssuerName>
     <X509SerialNumber>837113432321</X509SerialNumber>
   </X509IssuerSerial>
   ```

* `x509_cert_direct` gives you a `KeyInfo` with the `X509Data` directly embedding the certificate, like this:
  ```xml
  <KeyInfo>
     <X509Data>
       <X509Certificate>MIICAjCCAWu....7BQnulQ=</X509Certificate>
     </X509Data>
   </KeyInfo>
  ```

* `rsa_key_value` gives you a `KeyInfo` with a `KeyValue` element, like this:
  ```xml
  <KeyInfo>
    <KeyValue>
       <RSAKeyValue>
         <Modulus>B6PenDyT58LjZlG6LYD27IFCh1yO+4...yCP9YNDtsLZftMLoQ==</Modulus>
         <Exponent>AQAB</Exponent>
       </RSAKeyValue>
     </KeyValue>
   </KeyInfo>
  ```

All of these are valid according to the WS-Security standard. In all cases, the sender and
receiver of a signed document must agree on which configuration to use.


### Validating

Here's an example policy configuration:

```xml
<JavaCallout name='Java-WSSEC-Validate'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='max-lifetime'>10m</Property>
    <Property name='accept-thumbprints'>ada3a946669ad4e6e2c9f81360c3249e49a57a7d</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.wssecdsig.Validate</ClassName>
  <ResourceURL>java://apigee-wssecdsig-20241129.jar</ResourceURL>
</JavaCallout>
```

This will:

- verify a WS-Security signature on the specified document, by default requiring
  that both soap:Body and wsu:Timestamp are signed.

- It will by default verify that both a Created and an Expires element exist in
  the Timestamp. It will require that the timespan between the Created and
  Expires times does not exceed 10 minutes.

- It will validate only a signed document that includes an embedded
  certificate. It will check that the embedded cert is valid (not expired and
  not being used before its not-before date).  It will also check that the
  base16-encoded (aka hex-encoded) SHA1 thumbprint on the embedded certificate
  matches that specified in the `accept-thumbprints` property.

To verify a signature, over both the soap:Body and the wsu:Timestamp elements,
but NOT require a Timestamp/Expires element, use this:

```xml
<JavaCallout name='Java-WSSEC-Validate'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='require-expiry'>false</Property>
    <Property name='accept-thumbprints'>ada3a946669ad4e6e2c9f81360c3249e49a57a7d</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.wssecdsig.Validate</ClassName>
  <ResourceURL>java://apigee-wssecdsig-20241129.jar</ResourceURL>
</JavaCallout>
```

To verify a signature, over both the soap:Body and the wsu:Timestamp elements,
but NOT require a Timestamp/Expires element, and _also_ enforce a subject common
name on the certificate, use this:

```xml
<JavaCallout name='Java-WSSEC-Validate'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='require-expiry'>false</Property>
    <Property name='accept-thumbprints'>ada3a946669ad4e6e2c9f81360c3249e49a57a7d</Property>
    <Property name='accept-subject-cns'>host.example.com</Property>
  </Properties>
  <ClassName>com.google.apigee.callouts.wssecdsig.Validate</ClassName>
  <ResourceURL>java://apigee-wssecdsig-20241129.jar</ResourceURL>
</JavaCallout>
```

The properties available for the Validate callout are:

| name                   | description |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `source`                 | optional. the variable name in which to obtain the source signed document to validate. Defaults to message.content |
| `signing-method`         | optional. Takes value `rsa-sha1` or `rsa-sha256`. Checks that the signing method on the document is as specified. If this property is not present, there is no check on the algorithm. |
| `digest-method`          | optional. Takes value `sha1` or `sha256`. Checks that the digest method for each reference is as specified. If this property is not present, there is no check on the algorithm. |
| `accept-thumbprints`     | optional. a comma-separated list of SHA-1 thumbprints of the certs which are acceptable signers. If any signature is from a cert that has a thumbprint other than that specified, the verification fails. Either this property, or the similar `accept-thumbprints-sha256` is required if the `certificate` property is not provided. You should specify only one of `accept-thumbprints` or `accept-thumbprints-256`. |
| `accept-thumbprints-sha256` | optional. a comma-separated list of SHA-256 thumbprints of the certs which are acceptable signers. If any signature is from a cert that has a thumbprint other than that specified, the verification fails. Either this property, or the similar `accept-thumbprints` is required if the `certificate` property is not provided. You should specify only one of `accept-thumbprints` or `accept-thumbprints-256`. |
| `accept-subject-cns`     | optional. a comma-separated list of common names (CNs) for the subject which are acceptable signers. If any signature is from a CN other than that specified, the verification fails. |
| `require-expiry`         | optional. true or false, defaults true. Whether to require an expiry in the timestamp.  It is highly recommended that you use 'true' here, or just omit this property and accept the default. |
| `required-signed-elements` | optional. a comma-and-maybe-space-separated list of prefix:Tag forms indicating the elements that must be signed. Defaults to `soap:Body, wsu:Timestamp` . To require only a signature on the `wsu:Timestamp` and not the `soap:Body` when validating, set this to `wsu:Timestamp`.  (You probably don't want to do this.) To require only a signature on the `Body` and not the `Timestamp` when validating, set this to `soap:Body`. (You probably don't want to do this, either.) Probably you want to just leave this element out of your configuration and accept the default. Case is significant for the prefix and the tag. The predefined prefixes are listed below. |
| `ignore-expiry`          | optional. true or false. defaults false. When true, tells the validator to ignore the `Timestamp/Expires` field when evaluating validity of the soap message.  |
| `ignore-certificate-expiry` | optional. true or false. defaults false. When true, tells the validator to ignore any validity dates on the provided certificate. Useful mostly for testing. |
| `ignore-security-header-placement` | optional. true or false, defaults false. When true, tells the validator to not check the placement of the Security header in the signed payload. For compatibility with some legacy systems. This is not recommended because it can expose you to [signature wrapping attacks](https://secops.group/xml-signature-wrapping/). |
| `max-lifetime`           | optional. Takes a string like `120s`, `10m`, `4d`, etc to imply 120 seconds, 10 minutes, 4 days.  Use this to limit the acceptable lifetime of the signed document. This requires the Timestamp to include a Created as well as an Expires element. Default: no maximum lifetime. |
| `throw-fault-on-invalid` | optional. true or false, defaults to false. Whether to throw a fault when the signature is invalid, or when validation fails for another reason (wrong elements signed, lifetime exceeds max, etc). |
| `certificate`            | optional. The certificate that provides the public key to verify the signature. This is required (and used) only if the KeyInfo in the signed document does not explicitly provide the Certificate.  |
| `issuer-name-style`      | optional. One of {`CN`, `DN`}.  Used only if the signed document includes a KeyInfo that wraps X509IssuerSerial. See below for further details. |
| `issuer-name-dn-comparison` | optional. One of {`string`, `normal`, `reverse`, `unordered`}, default is `string`. Applies only if the signed document includes a KeyInfo that wraps X509IssuerSerial and the `issuer-name-style` is `DN` (which is the default). See below for further details. |
| `issuer-name-dn-comparison-exclude-numeric-oids`  | optional. true/false. Applies only if the signed document includes a KeyInfo that wraps X509IssuerSerial and the `issuer-name-style` is `DN`, and `issuer-name-dn-comparison` is `normal`, `reverse` or `unordered`. See below for further details. |


The result of the Validate callout is to set a single variable: `wssec_valid`.
It takes a true value if the signature was valid; false otherwise. You can use a
Condition in your Proxy flow to examine that result.  If the document is
invalid, then the policy will also throw a fault if the `throw-fault-on-invalid`
property is true.

Further comments:

* The Validate callout checks for the presence of a Security header which uses the XML namespace
  `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd`.
  This is normally a child of the SOAP Header. This callout by default checks that placement,
  to protect against [XM Signature Wrapping attacks](https://secops.group/xml-signature-wrapping/), but
  you can disable the check using the property `ignore-security-header-placement`. See the table above.

* The Validate callout verifies signatures using x509v3 certificates that
  contain RSA public keys. The callout is not able to validate a signature using
  an embedded RSA key found in the signed document. (This is a reasonable
  feature enhancement; but it hasn't been requested yet.)

* Every certificate has a "thumbprint", which is just a SHA-1 or SHA-256 hash of
  the encoded certificate data. This thumbprint is unique among certificates.
  If the certificate is embedded within the signed document, then the Validate
  callout checks for certificate trust via these thumbprints. In that case, one
  of `accept-thumbprints` or `accept-thumbprints-sha256` is required; You must
  configure one of those properties when using the Validate callout on a signed
  document that embeds the certificate.

  When validating a signed document that does not embed the certificate, you
  must explicitly provide the certificate in the callout configuration via the
  `certificate` property. In that case `accept-thumbprints` and `accept-thumbprints-sha256` are
  ignored, because the assumption is that if you specify the certificate, you
  trust it.

* The `issuer-name-style` property is meaningful only if the incoming signed
  document includes a `KeyInfo` element, which wraps an `X509IssuerSerial`
  element. Signers can use a brief form, specifying only the CN of the issuer
  (e.g. `CN=xxx`), or a full DN style, of a structure similar to
  `CN=xxx,O=xxx,L=xxx,ST=xxx,C=US`.  By default the callout will infer the
  appropriate name style. Specify either `CN` or `DN` here to force the callout
  to use a particular style. If you use `DN` here, or leave it blank, there is
  an additional property `issuer-name-dn-comparison`, which accepts one of
  {`string`, `normal`, `reverse`, `unordered`}.

    * `string`: does a straight string
      comparison of the Issuer DN in the document, against the Issuer DN on the
      certificate.

    * `normal`, `reverse`, `unordered`: compares each RDN in the Issuer DN in
      the document, against the corresponding RDN from the Issuer DN on the
      certificate. In the `normal` case, the order is normal.  In the `reverse`
      case, the callout reverses the order of the RDNs before comparison; some
      signers do this. In the `unordered` case, the callout just checks that
      each RDN in the Issuer DN from the doc is present in the Issuer DN on the
      cert, without considering order. In all three of these options, there is
      another property, `issuer-name-dn-comparison-exclude-numeric-oids`, which
      tells the callout to exclude RDNs that begin with numbers. Sometimes, RDNs
      are encoded into strings using [an LDAP
      OID](https://ldap.com/ldap-oid-reference-guide/), rather than a string,
      for the attribute type.  For example, the OID `1.2.840.113549.1.9.1`
      refers to an `emailAddress` attribute. If a signed document uses numeric
      OIDs for some RDNs, the straight "string comparison" will fail. This
      property can work around that interoperability issue.


* With the `max-lifetime` property, you can configure the policy to reject a
  signature that has a lifetime greater, say, 5 minutes. The maximum lifetime of
  a signed documented is computed from the asserted (and, ideally signed)
  Timestamp, by computing the difference between the Created and the Expires
  times. It does not make sense to specify `max-lifetime` if you also specify
  `required-signed-elements` to not include Timestamp, for an obvious reason: If
  the signature does not sign the Timestamp, it means any party can change the
  Timestamp, and therefore the computed lifetime of the document would be
  untrustworthy.

* it is possible to configure the policy with `require-expiry` = true and
  `ignore-expiry` = true.  While this seems nonsensical, it can be useful in
  testing scenarios. It tells the policy to check that an Expires element is
  present in the Timestamp, but do not evaluate the value of the element. This
  will be wanted rarely if ever, in a production situation.

* There is a `wssec_error` variable that gets set when the validation check fails.
  It will give you some additional information about the validation failure.

* For specifying which elements must be checked for signature in the
  `required-signed-elements` property, there is no way to define a prefix in the
  policy configuration. Instead you must select a prefix from the set of
  available "conventional" prefixes known by this callout. These are:

  | prefix     | namespace |
  | ---------- | --------- |
  | `wsa`      | http://www.w3.org/2005/08/addressing |
  | `wsu`      | http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd |
  | `soap`     |  either http://schemas.xmlsoap.org/soap/envelope/ for soap1.1 or http://www.w3.org/2003/05/soap-envelope for soap1.2|

  These are the only prefixes available to check.

  As an example, if your document uses `soapenv` as the prefix for the soap1.1 namespace, then you
  can use a string like `soap:Body` in the `required-signed-elements` property to require that
  the callout validate that the Body element has been signed.

See [the example API proxy included here](./bundle) for a working example of these policy configurations.

#### About Signature Wrapping attacks

There is a well-described technique for attacking XML signatures, called
["signature wrapping"](https://www.ws-attacks.org/XML_Signature_Wrapping).  It
involves modifying the signed document in such a way that the verifier still
verifies a signature, but the signature is on the wrong element in the document.
The actual body gets replaced with malicious content.

This callout is not vulnerable to the signature wrapping attack, because it
verifies that the Body and Timestamp are signed, and that they appear in the
expected places in the XML document, and that there is exactly one WS-Security
Security element, and that it is a direct child of the SOAP Header element.

Regarding the check on placement, if you have a signed SOAP document that looks like this:
```
<soapenv:Envelope
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:oas="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:ser="http://webservices.cashedge.com/services"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <soapenv:Header>
      <ser:AuthHeader>
        <ser:HomeID>redacted</ser:HomeID>
        <!-- In this document, the Security element is not a child of the soap Header. -->
        <oas:Security>
          <oas:UsernameToken>
            <oas:Username>redacted</oas:Username>
            <oas:Password>redacted</oas:Password>
          </oas:UsernameToken>
        </oas:Security>
      </ser:AuthHeader>
```

...the callout will, by default, reject that because the Security element is not
a direct child of the soap Header.

You can disable the check of the placement of the Security header, by setting
the property `ignore-security-header-placement` to the value `true`. In that
case, the Validate callout would treat a signed document structured as above, to
be valid.

## Example API Proxy Bundle

Deploy the API Proxy to an organization and environment using a tool like [importAndDeploy.js](https://github.com/DinoChiesa/apigee-edge-js-examples/blob/main/importAndDeploy.js)
or [apigeecli](https://github.com/apigee/apigeecli/blob/main/docs/apigeecli.md).

There are some sample SOAP request documents included in this repo that you can use for demonstrations.

### Invoking the Example proxy:

* Signing with Timestamp but no expiry, using BinarySecurityToken

   ```
   # Apigee Edge
   endpoint=https://${ORG}-${ENV}.apigee.net

   # Apigee X or hybrid
   endpoint=https://my-api-endpoint.net

   curl -i $endpoint/wssec/sign1  -H content-type:application/xml \
       --data-binary @./sample-data/request1.xml
   ```

* Signing with Timestamp that includes an expiry, with BinarySecurityToken

   ```
   curl -i $endpoint/wssec/sign2  -H content-type:application/xml \
       --data-binary @./sample-data/request1.xml
   ```
* Signing with Timestamp and expiry, emitting KeyInfo containing X509IssuerSerial

   ```
   curl -i $endpoint/wssec/sign3  -H content-type:application/xml \
       --data-binary @./sample-data/request1.xml
   ```
* Signing with Timestamp and expiry, emitting KeyInfo containing X509Data (raw certificate)

   ```
   curl -i $endpoint/wssec/sign4  -H content-type:application/xml \
       --data-binary @./sample-data/request1.xml
   ```
* Signing with Timestamp and expiry, emitting KeyInfo containing Thumbprint

   ```
   curl -i $endpoint/wssec/sign5  -H content-type:application/xml \
       --data-binary @./sample-data/request1.xml
   ```
* Signing, emitting KeyInfo with raw RSA Key

   ```
   curl -i $endpoint/wssec/sign6  -H content-type:application/xml \
       --data-binary @./sample-data/request1.xml
   ```
* Signing with SHA256 and RSA-SHA256 digest and signature methods

   ```
   curl -i $endpoint/wssec/sign7  -H content-type:application/xml \
       --data-binary @./sample-data/request1.xml
   ```
* Validating with hardcoded Common Name

   ```
   curl -i $endpoint/wssec/validate1  -H content-type:application/xml \
       --data-binary @./sample-data/signed-request.xml
   ```
   The output of the above should indicate that the signature on the document is
   valid.

* Validating with hardcoded Common Name, and a message with an expiry

   ```
   curl -i $endpoint/wssec/validate1  -H content-type:application/xml \
       --data-binary @./sample-data/signed-expiring-request.xml
   ```
   The output of the above should indicate that the message is expired.

* Validating with parameterized Thumbprint

   ```
   curl -i $endpoint/wssec/validate2?thumbprint=xxxyyyyzzz \
       -H content-type:application/xml \
       --data-binary @./sample-data/signed-request.xml
   ```
   The output of the above should indicate that the signature on the document is
   not valid, because the thumbprint provided does not match the thumbprint on
   the cert used to sign the document.

   ```
   curl -i $endpoint/wssec/validate2?thumbprint=ada3a946669ad4e6e2c9f81360c3249e49a57a7d \
       -H content-type:application/xml \
       --data-binary @./sample-data/signed-request.xml
   ```
   The output of the above should indicate that the signature on the document is
   valid, because the thumbprint provided matches the thumbprint on the cert
   that was used to sign the document.

* Validating with specified digest and signing method

   ```
   curl -i $endpoint/wssec/validate3  -H content-type:application/xml \
       --data-binary @./sample-data/signed-request-nonexpiring-sha256.xml
   ```
   The output of the above should indicate that the message is valid.


### Example of Signed Output

Supposing the input XML looks like this:

```xml
<soapenv:Envelope
    xmlns:ns1='http://ws.example.com/'
    xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>
  <soapenv:Body>
    <ns1:sumResponse>
      <ns1:return>9</ns1:return>
    </ns1:sumResponse>
  </soapenv:Body>
</soapenv:Envelope>
```

Then, given the default settings for `digest-method`, `signing-method`, and `key-identifier-type`,
the signed payload looks like this:

```xml
<soapenv:Envelope
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:ns1="http://ws.example.com/"
    xmlns:wssec="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <soapenv:Header>
    <wssec:Security soapenv:mustUnderstand="1">
      <wsu:Timestamp wsu:Id="Timestamp-57cd5229-1827-4fb7-a3fd-e9fd98dcd243">
        <wsu:Created>2019-10-08T10:25:57Z</wsu:Created>
      </wsu:Timestamp>
      <wssec:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="SecurityToken-24acaa0b-6643-40ef-be10-b5b65195bc12">MIIDpDCCAowCCQCVwuB4ec2igTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMDE0MTlaFw0yOTEwMDUxMDE0MTlaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApTEZRbMzhzl29R9SQ6mpo4Bz5DlvxbupLzelu6xPvi1K8JAd5GdKlvImUobDYznNUlvSxSQgJb8FNYFQ9Ty6jDle2+nOo8jIWf/FRByzRz+q7dGVNk2ngYteAfnjM62pFzb+asrxMNexP6atJukdcq3RpBac4FTTreHr68rvYlXs0/GpHj6sDXiguf+921aMb7ox0BGiuh4ydzPMofXXL4IF8HJQoUkXvJ7FGEGqK5R78/FcOvOzMim2TOKuO2TraUFtezFvUG0waTOGexhUfFI4AKD8lHuR0SlAThniVYs9P+X+ySmv/G/aYJPeYq4Lh3Ox1fUkE8EcSPvqqfzD1wIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAjsv6qkiUjoOOKMVMxkUtfNzbRKbpv4wDL4PR4mavPxRfJC9X9b5hozSkyOaxqkJ4XUwqXS9PwI3/D47P5kuLS5Q7sWHbphKFgJf5r8RAX5c3LjImodwPebrRXfouvQXn55LUDBFMEVp8fZOL10FRP0RIT22C7tAhU9eL8khSW0mPv+CNC410mDlxDat9N7RPC/EOxfroFk8Wv29rTRSR5boSdSFaPQkm8LjNW8VimdMu1qEg4sRlcEJlfQFE2ZojdhJGfftSXCOm+rin8MSzG6SE2fDrq44evnamzC321CebW16KoTcrFf4W/jCXdZx5iWLlvgK5XOhz9BmNo8Fal</wssec:BinarySecurityToken>
      <Signature
          xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
          <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
          <Reference URI="#Body-97d94bd5-96d8-46e6-ad55-a3f1e12a413b">
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
            <DigestValue>l3Wd6rPSvwISidh/HI6YH8iXwdw=</DigestValue>
          </Reference>
          <Reference URI="#Timestamp-57cd5229-1827-4fb7-a3fd-e9fd98dcd243">
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
            <DigestValue>TM7h1jcO4sRjxufRJ2cToXFvdnQ=</DigestValue>
          </Reference>
        </SignedInfo>
        <SignatureValue>CWaL/zScIG5Yb70mpCreSmEQQihemDJbmkQlGQ5m+xlMUW53oY1ReUg8iCQg2YEsa5QwKqHEj0yJ
        3X3FF1uJIjlQoAT8n+f0lLcDDRYOp239fwIzY6fFhLdwzsD/hKHzzDnV7Q/fEviywGsR4Gknxtrt
        tIoMiXIeMLWEWeiyteaefhhJcyNrE8nxbtPDcJFHm+gE8buFYAf7U2290lt7vfu8UKHTYBDrvGfb
        CIIyZUJeEX99e3o+fC4CUtiA4UEnHtDI3Z4ifPhkhJ+DYdTWQfejMKj8R5HiW9Pq5JZyUVYCK3bc
        Na9z4UZsLsVglRjzUIBzciuQ09Yw6f9yg3dBlA==</SignatureValue>
        <KeyInfo>
          <wssec:SecurityTokenReference>
            <wssec:Reference URI="#SecurityToken-24acaa0b-6643-40ef-be10-b5b65195bc12" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
          </wssec:SecurityTokenReference>
        </KeyInfo>
      </Signature>
    </wssec:Security>
  </soapenv:Header>
  <soapenv:Body wsu:Id="Body-97d94bd5-96d8-46e6-ad55-a3f1e12a413b">
    <ns1:sumResponse>
      <ns1:return>9</ns1:return>
    </ns1:sumResponse>
  </soapenv:Body>
</soapenv:Envelope>
```

This example has been prettified. The signed document will not be pretty-printed
like that; applying an XML Digital Signature will collapse whitespace. If you do
"pretty print" the signed document, you may render the signature
invalid. Whitespace matters.

## About Keys

There is a private RSA key and a corresponding certificate embedded in the API
Proxy. *You should not use those for your own purposes.* Create your
own keypair and certificate. Self-signed certificates are fine for testing purposes. You can
do it with openssl. Creating a privatekey, a certificate signing request, and a
certificate, is as easy as 1, 2, 3:

```
 openssl genpkey  -algorithm rsa -pkeyopt  rsa_keygen_bits:2048 -out privatekey.pem
 openssl req -key privatekey.pem -new -out domain.csr
 openssl x509 -req -days 3650 -in domain.csr -signkey privatekey.pem -out domain.cert
```

## Support

This callout is open-source software, and is not a supported part of Apigee.  If
you need assistance, you can try inquiring on [the Google Cloud Community forum
dedicated to Apigee](https://goo.gle/apigee-community) There is no service-level
guarantee for responses to inquiries posted to that forum; we do the best we can!



## Bugs

* Limitation: The Sign callout always uses XML Canonicalization, never uses Transform.ENVELOPED.
