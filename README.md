# Java Callout for WS-Security Digital Signature

This repo contains the Java source code and pom.xml file required to compile a
simple Java callout for Apigee, that creates or validates a signed SOAP
document that complies with the WS-Security standard. This repo also contains
the packaged jar.

There's a great deal of flexibility in the WS-Security standard, in terms of how
signatures are generated and embedded into a document, and how keys are
referenced. This callout in particular supports:

- RSA key pairs
- Signing or validating with RSA-SHA1 (http://www.w3.org/2000/09/xmldsig#rsa-sha1 ) or RSA-SHA256 (http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 ). The latter is highly recommended.
- When signing, signing either the soap:Body, or the wssec:Security/wsu:Timestamp element, or both. Signing both is highly recommended.
- using a digest method of sha1 (http://www.w3.org/2000/09/xmldsig#sha1) or sha256 (http://www.w3.org/2001/04/xmlenc#sha256) . The latter is highly recommended.
- When validating, validating either the Body, or the Timestamp, or both.
- Validating signatures via public keys embedded in X509v3 certificates.
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

This material is Copyright 2018-2022, Google LLC.
and is licensed under the Apache 2.0 license. See the [LICENSE](LICENSE) file.

This code is open source but you don't need to compile it in order to use it.

## Building

You do not need to build this callout in order to use it. You can build it if
you wish. To do so, use [Apache Maven](https://maven.apache.org/). You need maven v3.5 at a minimum.

```
mvn clean package
```

The 'package' goal will copy the jar to the resources/java directory for the
example proxy bundle. If you want to use this in your own API Proxy, you need
to copy this JAR into the appropriate API Proxy bundle. Or include the jar as an
environment-wide or organization-wide jar via the Apigee administrative API.


## Details

There is a single jar, apigee-wssecdsig-20221012.jar . Within that jar, there are two callout classes,

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
* If a Timestamp is present in the WS-Security header, validates expiry.
* Optionally _require_ that a Timestamp is present in the WS-Security header, with an Expires element.
* Optionally enforce a maximum lifetime of the signature. This is the difference between Created and Expires within the Timestamp. You may wish to limit this to 5 minutes, for example.
* verify that a specific digest method - sha-1 or sha-256 - is used when signing.

## Dependencies

Make sure these JARs are available as resources in the  proxy or in the environment or organization.

* Bouncy Castle: bcprov-jdk15on-1.62.jar, bcpkix-jdk15on-1.62.jar

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
  <ResourceURL>java://apigee-wssecdsig-20221012.jar</ResourceURL>
</JavaCallout>
```

There are a number of available properties for configuring the Sign callout, to
affect the shape of the signed document. This affects things like what elements
to sign, which signature method to use, the desired format of the Key
Information, and much more. These properties are described in detail here:

| name                 | description |
| -------------------- | ------------ |
| source               | optional. the variable name in which to obtain the source document to sign. Defaults to message.content |
| soap-version         | optional. Either `soap1.1` or `soap1.2`. Defaults to `soap1.1` . |
| output-variable      | optional. the variable name in which to write the signed XML. Defaults to message.content |
| private-key          | required. the PEM-encoded RSA private key. You can use a variable reference here as shown above. Probably you want to read this from encrypted KVM. |
| private-key-password | optional. The password for the key, if it is encrypted. |
| key-identifier-type  | optional. One of {`BST_DIRECT_REFERENCE`, `THUMBPRINT`,  `ISSUER_SERIAL`, `X509_CERT_DIRECT`, or `RSA_KEY_VALUE`}.  Defaults to `BST_DIRECT_REFERENCE`. See below for details on these options. |
| issuer-name-style    | optional. One of {`SHORT`, `SUBJECT_DN`}.  See below for details. |
| certificate          | required. The certificate matching the private key. In PEM form. |
| signing-method       | optional. Takes value `rsa-sha1` or `rsa-sha256`. Defaults to `rsa-sha1`. Despite this, `rsa-sha256` is highly recommended. |
| digest-method        | optional. Takes value `sha1` or `sha256`. Defaults to `sha1`. If you have the flexibility to do so, it's preferred that you use `sha256`. |
| elements-to-sign     | optional. Takes a comma-separated value. parts can include "timestamp" and "body". Nothing else. Default: the signer signs both the Timestamp and the soap:Body. |
| expiry               | optional. Takes a string like 120s, 10m, 4d, etc to imply 120 seconds, 10 minutes, 4 days. Default: no expiry. |
| c14-inclusive-elements | optional. Takes a comma-separated value of namespace _URIs_ (not prefixes). Used to add an InclusiveElements element to the CanonicalizationMethod element.  |
| transform-inclusive-elements | optional. Takes a comma-separated value of namespace _URIs_ (not prefixes). Used to add an InclusiveElements element to the Transform element.  |
| ds-prefix            | optional. A simple string, to be used as the prefix for the namespace "http://www.w3.org/2000/09/xmldsig#". Some users have expressed a desire to control this, and this callout makes it possible. This property affects the aesthetics of the document only, does not affect the XML InfoSet. |

This policy will sign the entire document and embed a Signature element as a child of the root element.

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

  For this case, you can optionally specify another property, `issuer-name-style`, as
  either `short` or `subject_dn`.  The former is the default, and an example for
  that is shown above. The latter provides the full distinguished name, which
  results in something like this:

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

All of these are valid according to the WS-Security standard. The sender and
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
  <ResourceURL>java://apigee-wssecdsig-20221012.jar</ResourceURL>
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
  <ResourceURL>java://apigee-wssecdsig-20221012.jar</ResourceURL>
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
  <ResourceURL>java://apigee-wssecdsig-20221012.jar</ResourceURL>
</JavaCallout>
```

The properties available for the Validate callout are:

| name                   | description |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------ |
| source                 | optional. the variable name in which to obtain the source signed document to validate. Defaults to message.content |
| signing-method         | optional. Takes value `rsa-sha1` or `rsa-sha256`. Checks that the signing method on the document is as specified. If this property is not present, there is no check on the algorithm. |
| digest-method          | optional. Takes value `sha1` or `sha256`. Checks that the digest method for each reference is as specified. If this property is not present, there is no check on the algorithm. |
| accept-thumbprints     | optional. a comma-separated list of SHA-1 thumbprints of the certs which are acceptable signers. If any signature is from a cert that has a thumbprint other than that specified, the verification fails. Required if the `certificate` property is not provided. There is no support for validating SHA256 thumbprints at this time. |
| accept-subject-cns     | optional. a comma-separated list of common names (CNs) for the subject which are acceptable signers. If any signature is from a CN other than that specified, the verification fails. |
| require-expiry         | optional. true or false, defaults true. Whether to require an expiry in the timestamp.  It is highly recommended that you use 'true' here, or just omit this property and accept the default. |
| required-signed-elements | optional. a comma-separated list of elements that must be signed. Defaults to `body,timestamp` . To require only a signature on the `wsu:Timestamp` and not the `soap:Body` when validating, set this to "timestamp". (You probably don't want to do this.) To require only a signature on the `Body` and not the `Timestamp` when validating, set this to `body`. (You probably don't want to do this, either.) Probably you want to just leave this element out of your configuration and accept the default. |
| ignore-expiry          | optional. true or false. defaults false. When true, tells the validator to ignore the Timestamp/Expires field when evaluating validity.    |
| max-lifetime           | optional. Takes a string like `120s`, `10m`, `4d`, etc to imply 120 seconds, 10 minutes, 4 days.  Use this to limit the acceptable lifetime of the signed document. This requires the Timestamp to include a Created as well as an Expires element. Default: no maximum lifetime. |
| throw-fault-on-invalid | optional. true or false, defaults to false. Whether to throw a fault when the signature is invalid, or when validation fails for another reason (wrong elements signed, lifetime exceeds max, etc). |
| certificate            | optional. The certificate that provides the public key to verify the signature. This is required (and used) only if the KeyInfo in the signed document does not explicitly provide the Certificate.  |
| issuer-name-style      | optional. One of {`SHORT`, `SUBJECT_DN`}.  Used only if the signed document includes a KeyInfo that wraps X509IssuerSerial. See the description under the Sign callout for further details. |


The result of the Validate callout is to set a single variable: wssec_valid.
It takes a true value if the signature was valid; false otherwise. You can use a
Condition in your Proxy flow to examine that result.  If the document is
invalid, then the policy will also throw a fault if the throw-fault-on-invalid
property is true.

Further comments:

* The Validate callout verifies signatures using x509v3 certificates that
  contain RSA public keys. The callout is not able to validate a signature using
  an embedded RSA key found in the signed document. (This is a reasonable
  feature enhancement; but it hasn't been requested yet.)

* Every certificate has a "thumbprint", which is just a SHA-1 hash of the
  encoded certificate data. This thumbprint is unique among certificates.  If
  the certificate is embedded within the signed document, then the Validate
  callout checks for certificate trust via these thumbprints. In that case,
  `accept-thumbprints` is required; You must configure it when using the
  Validate callout on a signed document that embeds the certificate. When
  validating a signed document that does not embed the certificate, you must
  explicitly provide the certificate in the callout configuration via the
  `certificate` property. In that case the `accept-thumbprints` property is
  ignored, because the assumption is that if you specify the certificate, you
  trust it. It is not possible to check the SHA-256 thumbprint at this
  time. This is a reasonable feature enhancement; but it hasn't been requested
  yet.

* With the `max-lifetime` property, you can configure the policy to reject a
  signature that has a lifetime greater, say, 5 minutes. The maximum lifetime of
  a signed documented is computed from the asserted (and, ideally signed)
  Timestamp, by computing the difference between the Created and the Expires
  times. It does not make sense to specify `max-lifetime` if you also specify
  `required-signed-elements` to not include Timestamp, for an obvious reason: If
  the signature does not sign the timestamp, it means any party can change the
  timestamp, and therefore the computed lifetime of the document would bve
  untrustworthy.

* it is possible to configure the policy with `require-expiry` = true and
  `ignore-expiry` = true.  While this seems nonsensical, it can be useful in
  testing scenarios. It tells the policy to check that an Expires element is
  present in the Timestamp, but do not evaluate the value of the element. This
  will be wanted rarely if ever, in a production situation.

* There is a `wssec_error` variable that gets set when the validation check fails.
  It will give you some additional information about the validation failure.



See [the example API proxy included here](./bundle) for a working example of these policy configurations.

#### About Signature Wrapping attacks

There is a well-described technique for attacking XML signatures, called
["signature wrapping"](https://www.ws-attacks.org/XML_Signature_Wrapping).  It
involves modifying the signed document in such a way that the verifier still
verifies a signature, but the signature is on the wrong element in the document.
The actual body gets replaced with malicious content.

This callout is not vulnerable to the signature wrapping attack, because it
verifies that the Body and Timestamp are signed, and that they appear in the
expected places in the XML document.

## Example API Proxy Bundle

Deploy the API Proxy to an organization and environment using a tool like [importAndDeploy.js](https://github.com/DinoChiesa/apigee-edge-js-examples/blob/main/importAndDeploy.js)

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


## Bugs

* Limitation: The Sign callout always uses XML Canonicalization, never uses Transform.ENVELOPED.
* The Validate callout cannot check the SHA-256 thumbprint of a signing certificate, only SHA-1.
