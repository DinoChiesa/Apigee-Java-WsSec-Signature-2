# Java Callout for WS-Security Digital Signature

This directory contains the Java source code and pom.xml file required
to compile a simple Java callout for Apigee Edge, that creates or validates
a digital signature that complies with WS-Security standard, using an x509v3
Binary Security Token.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## License

This material is Copyright 2018-2019, Google LLC.
and is licensed under the Apache 2.0 license. See the [LICENSE](LICENSE) file.

This code is open source but you don't need to compile it in order to use it.

## Details

There are two callout classes,

* com.google.apigee.edgecallouts.wssecdsig.Sign - signs the input SOAP document.
* com.google.apigee.edgecallouts.wssecdsig.Validate - validates the signed SOAP document

The Sign callout has these constraints and features:
* supports RSA algorithms - rsa-sha1 (default) or rsa-sha256
* Will automatically add a Timestamp to the WS-Security header
* Can optionally add an Expiry to that timestamp
* signs the SOAP Body, or the Timestamp, or both (default)
* uses a canonicalization method of "http://www.w3.org/2001/10/xml-exc-c14n#"
* uses a digest mode of sha1 (default) or sha256

The Verify callout has these constraints and features:
* supports RSA algorithms - rsa-sha1 (default) or rsa-sha256
* If a Timestamp is present in the WS-Security header, validates expiry.

## Dependencies

Make sure these JARs are available as resources in the  proxy or in the environment or organization.

* Bouncy Castle: bcprov-jdk15on-1.60.jar, bcpkix-jdk15on-1.60.jar

This Callout does not depend on WSS4J.  The WSS4J is prohibited from use within
Apigee SaaS, due to Java permissions settings. This callout is intended to be
usable in Apigee SaaS.

## Usage

### Signing

Configure the policy this way:

```xml
<JavaCallout name='Java-WSSEC-Sign'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='output-variable'>output</Property>
    <Property name='private-key'>{my_private_key}</Property>
    <Property name='certificate'>{my_certificate}</Property>
  </Properties>
  <ClassName>com.google.apigee.edgecallouts.wssecdsig.Sign</ClassName>
  <ResourceURL>java://edge-wssecdsig-20191008.jar</ResourceURL>
</JavaCallout>
```

The properties are:

| name                 | description |
| -------------------- | ------------ |
| source               | optional. the variable name in which to obtain the source document to sign. Defaults to message.content |
| output-variable      | optional. the variable name in which to write the signed XML. Defaults to message.content |
| private-key          | required. the PEM-encoded RSA private key. You can use a variable reference here as shown above. Probably you want to read this from encrypted KVM. |
| private-key-password | optional. The password for the key, if it is encrypted. |
| certificate          | required. The certificate matching the private key. In PEM form. |
| signing-method       | optional. Takes value rsa-sha1 or rsa-sha256. Defaults to rsa-sha1. |
| digest-method        | optional. Takes value sha1 or sha256. Defaults to sha1. |
| elements-to-sign     | optional. Takes a comma-separated value. parts can include "timestamp" and "body". Nothing else. Default: the signer signs both the timestamp and the soap body. |
| expiry               | optional. Takes a string like 120s, 10m, 4d, etc to imply 120 seconds, 10 minutes, 4 days.  Default: no expiry. |

This policy will sign the entire document and embed a Signature element as a child of the root element.

### Validating

Configure the policy this way:

```xml
<JavaCallout name='Java-WSSEC-Validate'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='common-names'>host.example.com</Property>
  </Properties>
  <ClassName>com.google.apigee.edgecallouts.wssecdsig.Validate</ClassName>
  <ResourceURL>java://edge-wssecdsig-20191008.jar</ResourceURL>
</JavaCallout>
```

This will verify a WS-Security signature on the specified document. It will by
default require a Timestamp and an Expires element.

To verify a signature and not require an expiry, use this:
```xml
<JavaCallout name='Java-WSSEC-Validate'>
  <Properties>
    <Property name='source'>message.content</Property>
    <Property name='require-expiry'>false</Property>
    <Property name='common-names'>host.example.com</Property>
  </Properties>
  <ClassName>com.google.apigee.edgecallouts.wssecdsig.Validate</ClassName>
  <ResourceURL>java://edge-wssecdsig-20191008.jar</ResourceURL>
</JavaCallout>
```

The properties are:

| name            | description |
| --------------- | ------------------------------------------------------------------------------------------------------------------ |
| source          | optional. the variable name in which to obtain the source signed document to validate. Defaults to message.content |
| common-names    | optional. a comma-separated list of common names (CNs) which are acceptable signers.                               |
| require-expiry  | optional. true or false, defaults true. Whether to require an expiry in the timestamp.  |
| required-signed-elements | optional. a Comma-separated list of elements that must be signed. Defaults to "body,timestamp" .   |
| ignore-expiry   | optional. true or false. defaults false. When true, tells the validator to ignore the Timestamp/Expires field when evaluating validity.    |
| throw-fault-on-invalid | optional. true or false, defaults to false. Whether to throw a fault when the signature is invalid. |


The result of the Validate callout is to set a single variable: xmldsig_valid.
It takes a true value if the signature was valid; false otherwise. You can use a
Condition in your Proxy flow to examine that result.  If the document is
invalid, then the policy will also throw a fault if the throw-fault-on-invalid
property is true.

See [the example API proxy included here](./bundle) for a working example of these policy configurations.


## Example API Proxy Bundle

Deploy the API Proxy to an organization and environment using a tool like [importAndDeploy.js](https://github.com/DinoChiesa/apigee-edge-js/blob/master/examples/importAndDeploy.js)

There are some sample SOAP request documents included in this repo that you can use for demonstrations.

There is a private RSA key and a corresponding certificate embedded in the API
Proxy. You should not use those for your own purposes. Create your own. You can
do it with openssl.


```
 openssl genpkey  -algorithm rsa -pkeyopt  rsa_keygen_bits:2048 -out privatekey.pem
 openssl req \
        -key privatekey.pem \
        -new -out domain.csr

 openssl x509 -req -days 3650 -in domain.csr -signkey privatekey.pem -out domain.cert
```

### Invoking the Example proxy:

* Signing with Timestamp but no expiry

   ```
   ORG=myorgname
   ENV=myenv
   curl -i https://${ORG}-${ENV}.apigee.net/wssec/sign1  -H content-type:application/xml \
       --data-binary @./sample-data/request1.xml
   ```

* Signing with Timestamp that includes an expiry

   ```
   curl -i https://${ORG}-${ENV}.apigee.net/wssec/sign2  -H content-type:application/xml \
       --data-binary @./sample-data/request1.xml
   ```
* Validating with hardcoded Common Name

   ```
   curl -i https://${ORG}-${ENV}.apigee.net/wssec/validate1  -H content-type:application/xml \
       --data-binary @./sample-data/signed-request.xml
   ```
   The output of the above should indicate that the signature on the document is
   valid.

* Validating with hardcoded Common Name, and a message with an expiry

   ```
   curl -i https://${ORG}-${ENV}.apigee.net/wssec/validate1  -H content-type:application/xml \
       --data-binary @./sample-data/signed-expiring-request.xml
   ```
   The output of the above should indicate that the message is expired.

* Validating with parameterized Common Name

   ```
   curl -i https://${ORG}-${ENV}.apigee.net/wssec/validate2?cn=abc.example.com \
       -H content-type:application/xml \
       --data-binary @./sample-data/signed-request.xml
   ```
   The output of the above should indicate that the signature on the document is
   not valid, because the common name is not acceptable.


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

...the signed payload looks like this:

```
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

## Bugs

None reported.
