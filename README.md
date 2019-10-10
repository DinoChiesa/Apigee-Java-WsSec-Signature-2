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
    <Property name='common-names>host.example.com</Property>
  </Properties>
  <ClassName>com.google.apigee.edgecallouts.wssecdsig.Validate</ClassName>
  <ResourceURL>java://edge-wssecdsig-20191008.jar</ResourceURL>
</JavaCallout>
```

The properties are:

| name            | description |
| --------------- | ------------ |
| source          | optional. the variable name in which to obtain the source signed document to validate. Defaults to message.content |
| common-names    | optional. a comma-separated list of common names (CNs) which are acceptable signers |
| ignore-timestamp| optional. true or false. When true, tells the validator to ignore the timestamp field when evaluating validity. |

The result of the Validate callout is to set a single variable: xmldsig_valid.
It takes a true value if the signature was valid; false otherwise. You can use a
Condition in your Proxy flow to examine that result.  If the document is
invalid, then the policy will also throw a fault. 


See [the example API proxy included here](./bundle) for a working example of these policy configurations.


## Example API Proxy Bundle

Deploy the API Proxy to an organization and environment using a tool like [importAndDeploy.js](https://github.com/DinoChiesa/apigee-edge-js/blob/master/examples/importAndDeploy.js)

There are some sample documents included in this repo that you can use for demonstrations.

There are two distinct private keys embedded in the API Proxy. Both are RSA keys. Key 1 was generated this way:

```
 openssl genpkey -aes-128-cbc -algorithm rsa \
     -pkeyopt rsa_keygen_bits:2048 \
     -out encrypted-genpkey-aes-128-cbc.pem
```

Key 2 generated with the "older" openssl syntax, this way:
```
openssl genrsa -des3 -out private-encrypted-DES-EDE3-CBC.pem 2048
```

Either form of PEM-encoded key works.

### Invoking the Example proxy:

* Signing with key 1

   ```
   ORG=myorgname
   ENV=myenv
   curl -i https://${ORG}-${ENV}.apigee.net/xmldsig/sign1  -H content-type:application/xml \
       --data-binary @./sample-data/order.xml
   ```

* Signing with key 2

   ```
   curl -i https://${ORG}-${ENV}.apigee.net/xmldsig/sign2  -H content-type:application/xml \
       --data-binary @./sample-data/order.xml
   ```
* Validating with key 1

   ```
   curl -i https://${ORG}-${ENV}.apigee.net/xmldsig/validate1  -H content-type:application/xml \
       --data-binary @./sample-data/order-signed1.xml
   ```
   The output of the above is "true", meaning "The signature on the document is valid."

* Validating with key 2

   ```
   curl -i https://${ORG}-${ENV}.apigee.net/xmldsig/validate2  -H content-type:application/xml \
       --data-binary @./sample-data/order-signed2.xml
   ```
   The output of the above is "true", meaning "The signature on the document is valid."

* Validation fails with incorrect key

   ```
   curl -i https://${ORG}-${ENV}.apigee.net/xmldsig/validate2  -H content-type:application/xml \
      --data-binary @./sample-data/order-signed1.xml
   ```
   Because order-signed1 was signed with private key 1, validating it against public key 2 (via /validate2) will return "false", meaning "The signature on the document is not valid."  This is expected.

* Validation fails with incorrect key, case 2

   ```
   curl -i https://${ORG}-${ENV}.apigee.net/xmldsig/validate1  -H content-type:application/xml \
       --data-binary @./sample-data/order-signed2.xml
   ```

   Because order-signed1 was signed with private key 2, validating it
   against public key 1 (via /validate1) will return "false", meaning
   "The signature on the document is not valid."  This is expected.



### Example of Signed Output

Supposing the input XML looks like this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<order>
  <customer customerNumber="0815A4711">
    <name>Michael Sonntag</name>
    <address>
      <street>Altenbergerstr. 69</street>
      <ZIP>4040</ZIP>
      <city>Linz</city>
    </address>
  </customer>
  <articles>
    <line>
      <quantity unit="piece">30</quantity>
      <product productNumber="9907">XML editing widget</product>
      <price currency="EUR">0.10</price>
    </line>
    <line>
      <quantity unit="litre">5</quantity>
      <product productNumber="007">Super juice</product>
      <price currency="HUF">500</price>
    </line>
  </articles>
  <delivery>
    <deliveryaddress>
      <name>Michael Sonntag</name>
      <address>
        <street>Auf der Wies 18</street>
      </address>
    </deliveryaddress>
  </delivery>
  <payment type="CC">
    <creditcard issuer="Mastercard">
      <nameOnCard>Mag. Dipl.-Ing. Dr. Michael Sonntag</nameOnCard>
      <number>5201 2345 6789 0123</number>
      <expiryDate>2006-04-30</expiryDate>
    </creditcard>
  </payment>
</order>
```

...the signed payload looks like this:

```
<?xml version="1.0" encoding="UTF-8" standalone="no"?><order>
  <customer customerNumber="0815A4711">
    <name>Michael Sonntag</name>
    <address>
      <street>Altenbergerstr. 69</street>
      <ZIP>4040</ZIP>
      <city>Linz</city>
    </address>
  </customer>
  <articles>
    <line>
      <quantity unit="piece">30</quantity>
      <product productNumber="9907">XML editing widget</product>
      <price currency="EUR">0.10</price>
    </line>
    <line>
      <quantity unit="litre">5</quantity>
      <product productNumber="007">Super juice</product>
      <price currency="HUF">500</price>
    </line>
  </articles>
  <delivery>
    <deliveryaddress>
      <name>Michael Sonntag</name>
      <address>
        <street>Auf der Wies 18</street>
      </address>
    </deliveryaddress>
  </delivery>
  <payment type="CC">
    <creditcard issuer="Mastercard">
      <nameOnCard>Mag. Dipl.-Ing. Dr. Michael Sonntag</nameOnCard>
      <number>5201 2345 6789 0123</number>
      <expiryDate>2006-04-30</expiryDate>
    </creditcard>
  </payment>
<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>Rtv+iAkC0p7hJbs3741vK/V7eV92EuEk+hb6IUXVhME=</DigestValue></Reference></SignedInfo><SignatureValue>w9Fqn9Dx22xh++HgU4YeyZ0ndYcWj17IHrV2eZ17dj2U5o3de2IAmvg2jdLJxs99GLstOonhv/cK
b7mzpI6tGyUTfGwhS5l1Ok8DFooxDT7KvJ6RXBuWFuuNYa+iN+fLbxBOg5D8gAOVC1qsOCas7bs8
CSkzVWRZRxl6JJuaOpyJ6xM3nIdkSAqGYnChljQuGI6UXgru/KKc4mASCjkyzknzoJa4fv9C2enY
9E7LZ4z+KqdtyK5xjifLXxfIIDAF+9hQUzIe+Wm4otZ0p7pQX6LEYVifkLoJbaLdsw8KTHYcF+XS
8d6qUENo/WnHp0dCLxzFZISnumCAt6DHHah3/A==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>B6PenDyGOg0P5vb5DfJ13DmjJi82KdPT58LjZlG6LYD27IFCh1yO+4ygJAxfIB00muiIuB8YyQ3T
JKgkJdEWcVTGL1aomN0PuHTHP67FfBPHgmCM1+wEtm6tn+uoxyvQhLkB1/4Ke0VA7wJx4LB5Nxoo
/4GCYZp+m/1DAqTvDy99hRuSTWt+VJacgPvfDMA2akFJAwUVSJwh/SyFZf2yqonzfnkHEK/hnC81
vACs6usAj4wR04yj5yElXW+pQ5Vk4RUwR6Q0E8nKWLfYFrXygeYUbTSQEj0f44DGVHOdMdT+BoGV
5SJ1ITs+peOCYjhVZvdngyCP9YNDtsLZftMLoQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature></order>
```

## Bugs

None reported.
