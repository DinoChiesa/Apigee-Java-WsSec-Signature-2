package com.google.apigee.edgecallouts.test;

import com.apigee.flow.execution.ExecutionResult;
import com.google.apigee.edgecallouts.wssecdsig.Validate;
import com.google.apigee.edgecallouts.wssecdsig.Sign;
import java.util.HashMap;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestWssecValidateCallout extends CalloutTestBase {

  private static final String emptyDocument = "";

  private static final String signedSoapWithExpiry1 =
      "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns1=\"http://ws.example.com/\" xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">  <soapenv:Header><wssec:Security soapenv:mustUnderstand=\"1\"><wsu:Timestamp wsu:Id=\"Timestamp-1a955a57-6e37-4b00-be3b-8bb6cb53a55e\"><wsu:Created>2019-10-11T22:54:33Z</wsu:Created><wsu:Expires>2019-10-11T23:09:33Z</wsu:Expires></wsu:Timestamp><wssec:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" wsu:Id=\"SecurityToken-97001b67-5f40-4bc1-8be3-c7deec352ce7\">MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</wssec:BinarySecurityToken><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#Body-e30cad12-ff22-442f-b54c-d0e091207651\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>xyRKsY2Yg0I/yFvG1M8Mh1RMu7s=</DigestValue></Reference><Reference URI=\"#Timestamp-1a955a57-6e37-4b00-be3b-8bb6cb53a55e\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>iQAv8Jkh8m8uBERX+0Gd5E5ZG08=</DigestValue></Reference></SignedInfo><SignatureValue>MBhXR0N5jVHADW4IWFTPOY0g4HNgp5IGrtU2stfGDhJ1B6UJ5YMTqnCDtDnz/S4csFmk+3yxqaoG\n"
          + "YS45sBGaKRq8rkYkxx3rWM94mwRvfqfdpXLlVOfETFBJg0rol2Er4OXzwkOl9hlLD3ngizORPC83\n"
          + "t1U6O574ElvP3JxBxmExngBhh4BNuT02V0FepsFCfbWJNEDCzfquR1CQvypcyGt4meBfYNu76N9C\n"
          + "GKwRQpuFQevpNsK3IEv1LbAW6mPNB4qDvU08+7Or3TWS7cfVE8fXRk1lQvG039ovytWMGCh1WFFX\n"
          + "4t+ONqa+UwC8sttkz+le4y15kfJhAxkOR+swTw==</SignatureValue><KeyInfo><wssec:SecurityTokenReference><wssec:Reference URI=\"#SecurityToken-97001b67-5f40-4bc1-8be3-c7deec352ce7\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/></wssec:SecurityTokenReference></KeyInfo></Signature></wssec:Security></soapenv:Header><soapenv:Body wsu:Id=\"Body-e30cad12-ff22-442f-b54c-d0e091207651\">    <ns1:sumResponse>      <ns1:return>9</ns1:return>    </ns1:sumResponse>  </soapenv:Body></soapenv:Envelope>";

  private static final String signedSoapNoExpiry1 =
      "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns1=\"http://ws.example.com/\" xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">  <soapenv:Header><wssec:Security soapenv:mustUnderstand=\"1\"><wsu:Timestamp wsu:Id=\"Timestamp-2360297c-f9aa-4eee-8d77-18dc879e5c96\"><wsu:Created>2019-10-10T03:11:33Z</wsu:Created></wsu:Timestamp><wssec:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" wsu:Id=\"SecurityToken-fc17c566-ca8f-4dc1-8831-5b7229308ea3\">MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</wssec:BinarySecurityToken><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#Body-2b0a6efc-3595-4400-a86d-2ec647f47a1c\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>cXimEY2UdfeKiEBzpd5hQn5DwG8=</DigestValue></Reference><Reference URI=\"#Timestamp-2360297c-f9aa-4eee-8d77-18dc879e5c96\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>i2VsQBraiZBSj91G1Y/5gd+B9io=</DigestValue></Reference></SignedInfo><SignatureValue>EDRJmfWQ6cQ0OcHAvB1fLLMYsbyGIUxwroYkyZ4EXvY+T6n9vi5YJ78dss6WDDtOvwBpO5drzqou\n"
          + "uOogfkRDXNqu81DyIUJm9VMtitX9ORMVAeNwF6oMAj2h/hfEjt+zaT7Nknaseq6t8U47GM5ZdxOr\n"
          + "T3WVbVjm3Z8AqvrKcdRgcsEhTXvk0JI1WNEwh5GxcYxwq7WouJQmLu3WkuTlRp5RpKDMEDhnxlnv\n"
          + "Mb5N1298Zcqn5kCFYm6IMYBx/iEGRuvXBlRnroD4bVov3JTCh1CahPoOUwVQAPG5yFmv0Bz7hHbr\n"
          + "0euQAtNitxzpea3NxhB2q4B+W2ufMMAxFnS1zA==</SignatureValue><KeyInfo><wssec:SecurityTokenReference><wssec:Reference URI=\"#SecurityToken-fc17c566-ca8f-4dc1-8831-5b7229308ea3\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/></wssec:SecurityTokenReference></KeyInfo></Signature></wssec:Security></soapenv:Header><soapenv:Body wsu:Id=\"Body-2b0a6efc-3595-4400-a86d-2ec647f47a1c\">    <ns1:sumResponse>      <ns1:return>9</ns1:return>    </ns1:sumResponse>  </soapenv:Body></soapenv:Envelope>\n";

  private static final String signedSoapMissingSecurityTokenReference =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns1=\"http://ws.example.com/\" xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">  <soapenv:Header><wssec:Security soapenv:mustUnderstand=\"1\"><wsu:Timestamp wsu:Id=\"Timestamp-b00f0f15-50d6-4e50-8841-38f9b3ae01cb\"><wsu:Created>2019-10-08T03:39:39Z</wsu:Created></wsu:Timestamp><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#Body-61274408-e24e-4df6-b1ec-612538ced7e6\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>5zMKTwWym107y+YwQoTmfiy6LqM=</DigestValue></Reference><Reference URI=\"#Timestamp-b00f0f15-50d6-4e50-8841-38f9b3ae01cb\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>SF8XRy854rxcfjgYn4sCt5IkMfw=</DigestValue></Reference></SignedInfo><SignatureValue>ksG/4U2hyJfgxIhekbLE8tXJ1/QCg7MhZuYoNnNIKj1jibBfDHkAo/p1XhYjMvZHdK7pR1XWvhDu\n"
          + "1XwfuUDFMFeCC4x4gY20f++tRX7BwnPiN9flIwBEn7ViUifPZ1nElMXdlDGJe9TmL8CN8TUvHkGa\n"
          + "y/gEMMmIMVuEayI7X/IzGcsefovw7LEELyAwTyK1IudeflnI2NPGmBVWHnl3Z06OPSYmRSmUWP85\n"
          + "OIrlI4fb8LE0iARofVawdgJj+iYut+3rsBhl4D3iwcrPZslPMBbCXqMzcJFNMxCKanDuMgog3UrL\n"
          + "eEdiicloTEnBlRK0ek40tZKrr1huTbJS8sfKrA==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>B6PenDyGOg0P5vb5DfJ13DmjJi82KdPT58LjZlG6LYD27IFCh1yO+4ygJAxfIB00muiIuB8YyQ3T\n"
          + "JKgkJdEWcVTGL1aomN0PuHTHP67FfBPHgmCM1+wEtm6tn+uoxyvQhLkB1/4Ke0VA7wJx4LB5Nxoo\n"
          + "/4GCYZp+m/1DAqTvDy99hRuSTWt+VJacgPvfDMA2akFJAwUVSJwh/SyFZf2yqonzfnkHEK/hnC81\n"
          + "vACs6usAj4wR04yj5yElXW+pQ5Vk4RUwR6Q0E8nKWLfYFrXygeYUbTSQEj0f44DGVHOdMdT+BoGV\n"
          + "5SJ1ITs+peOCYjhVZvdngyCP9YNDtsLZftMLoQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature></wssec:Security></soapenv:Header><soapenv:Body wsu:Id=\"Body-61274408-e24e-4df6-b1ec-612538ced7e6\">    <ns1:sumResponse>      <return>9</return>    </ns1:sumResponse>  </soapenv:Body></soapenv:Envelope>\n";

  private static final String signedSoapWithIssuerSerial =
"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:ns1=\"http://ws.example.com/\">\n"
+ "  <soapenv:Header><wssec:Security soapenv:mustUnderstand=\"1\"><wsu:Timestamp wsu:Id=\"Timestamp-466b8e6a-5404-403d-a12f-94aee405760d\"><wsu:Created>2019-11-21T17:31:40Z</wsu:Created><wsu:Expires>2019-11-21T17:36:40Z</wsu:Expires></wsu:Timestamp><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#Body-b8ec95ca-c7f1-497d-afdf-1144d98fe068\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>B83bgub0iAcsd39NYb3J2bpV2FU=</DigestValue></Reference><Reference URI=\"#Timestamp-466b8e6a-5404-403d-a12f-94aee405760d\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>RI6KMtZmnkirtnYqxqhuDrzBF70=</DigestValue></Reference></SignedInfo><SignatureValue>fOtgpaZyN1cGJa4JdNzKpYvgz/8tb28us/zbqEyAfDdmd+JhP2IjLpNf+x8+M5TtsNlMc16ta6/W\n"
+ "0KMDdKBP2qVJU8DROadHhpONwfSciWY8U/hH0K5X4zjr1zrA9ixdIYl0I4jLZ8Z6dlBDRchxYcNg\n"
+ "JrKrgw3KqpsXDRb97FHrPTwG67c30OHXzxFvqGkdlu7UV6XDCIzjsHgxEvq8MKPSRDHNod50cpyi\n"
+ "pQZn6ArOrilM7LcRlR4wQqW6jwi1OZMbGI0R4GeKtEH83Zvrgxf/wdanvoCymSvNLMvecx5Ir/US\n"
+ "KzyfmJZHM5ZoygtHJhN67gSKSu3h7RgFg5ogpQ==</SignatureValue><KeyInfo><wssec:SecurityTokenReference><X509Data><X509IssuerSerial><X509IssuerName>CN=apigee.google.com</X509IssuerName><X509SerialNumber>17032128222562009281</X509SerialNumber></X509IssuerSerial></X509Data></wssec:SecurityTokenReference></KeyInfo></Signature></wssec:Security></soapenv:Header><soapenv:Body wsu:Id=\"Body-b8ec95ca-c7f1-497d-afdf-1144d98fe068\">\n"
+ "    <ns1:sumResponse>\n"
+ "      <ns1:return>9</ns1:return>\n"
+ "    </ns1:sumResponse>\n"
+ "  </soapenv:Body>\n"
+ "</soapenv:Envelope>\n";

  private static final String signedSoapWithKeyInfoRawCert =
"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:ns1=\"http://ws.example.com/\">\n"
+ "  <soapenv:Header><wssec:Security soapenv:mustUnderstand=\"1\"><wsu:Timestamp wsu:Id=\"Timestamp-c4a1b3a5-57fa-4747-a27c-7534c0b29c34\"><wsu:Created>2019-11-21T19:24:55Z</wsu:Created></wsu:Timestamp><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#Body-92bdb04f-e124-479a-9978-9220ac84130b\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>BZYaq3hrrIF7l520PV3VTu3rTJ0=</DigestValue></Reference><Reference URI=\"#Timestamp-c4a1b3a5-57fa-4747-a27c-7534c0b29c34\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>H4B7MvA3pQO3ZxUe1d6w5fK/ErM=</DigestValue></Reference></SignedInfo><SignatureValue>eiPSfxLQbeQ9NUCuEpVY6aio6ClivAH9jAyAyJD033KQba9mCZelaKlLfg+1Q6jiaTOPjN3mx9ZX\n"
+ "JRQ03GvR/U3umRfxCHIz5QdWxpfTl665JXOSCJfiwGcbo4L/xVt+QkpdPsf2fNpbZihQOND4tb5r\n"
+ "FB/y0iTScVxhXabmOY9/XFFgEiqyrjrJ7wf+QCwD22vT15eLWZ/q5MICRN9IDgcKDN2ULQDBoMD5\n"
+ "WTKUln8UKtaM4XfWA6Dyfwsd/3dTKQlqmoZy/fmOS9L/Faobwmq7g2dxkQ0wCTNI3AvumSPX/yVD\n"
+ "YZCCt0pH8+M7newaaMmH8DIFlUt/36x1snGWuw==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEwMDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYgvdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9lYARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVIkxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl36iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZLklpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMBtqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4WjETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIReK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib</X509Certificate></X509Data></KeyInfo></Signature></wssec:Security></soapenv:Header><soapenv:Body wsu:Id=\"Body-92bdb04f-e124-479a-9978-9220ac84130b\">\n"
+ "    <ns1:sumResponse>\n"
+ "      <ns1:return>9</ns1:return>\n"
+ "    </ns1:sumResponse>\n"
+ "  </soapenv:Body>\n"
+ "</soapenv:Envelope>\n";

  private static final String signedSoapWithKeyInfoThumbprint =
"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wssec=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:ns1=\"http://ws.example.com/\">\n"
+ "  <soapenv:Header><wssec:Security soapenv:mustUnderstand=\"1\"><wsu:Timestamp wsu:Id=\"Timestamp-0bdbc910-099a-4e32-96e1-7391cbc5d23b\"><wsu:Created>2019-11-21T19:22:23Z</wsu:Created><wsu:Expires>2019-11-21T19:27:23Z</wsu:Expires></wsu:Timestamp><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#Body-6ae8814d-7a91-41ec-8261-ff177c245752\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>sTtJdgJQ7c+RJePuNjrRxtgYyM4=</DigestValue></Reference><Reference URI=\"#Timestamp-0bdbc910-099a-4e32-96e1-7391cbc5d23b\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>ZBN/UnJDJzAfwm1zMe2beUyPInM=</DigestValue></Reference></SignedInfo><SignatureValue>Kt4b1P/vC+TkzLho7LtM965U/n+X445cTesn7JAq7Q3wjvqdqKYM+MCDNP9P1yuVD7bdVpoGhcs6\n"
+ "hCTyPup4yepfW/ihsBYMRQt9IT7/j8QE2sUr+7A+V6vFEj8KeYCyfrcPbZPVVPD6HBIhQZ4l6+di\n"
+ "blNOaRWquHSjGAe/aueX4mhVtdWSvw3C4srrsleMqViP8z8C5lqONpl2cXz1n3YqtdAZBa9FXlAs\n"
+ "Kqrj0YmZbQp+MUOUE7LnSIWMEVcIKO1eXMpohfUeNlI7Qq0bFc5rI0Jeh1dn6m44kvkstG/W0AX1\n"
+ "nNLI+3gJTyMo7xXe2Yve2SNWov05trRJcwH1bQ==</SignatureValue><KeyInfo><wssec:SecurityTokenReference><wssec:KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security1.1#ThumbprintSHA1\">raOpRmaa1ObiyfgTYMMknkmlen0=</wssec:KeyIdentifier></wssec:SecurityTokenReference></KeyInfo></Signature></wssec:Security></soapenv:Header><soapenv:Body wsu:Id=\"Body-6ae8814d-7a91-41ec-8261-ff177c245752\">\n"
+ "    <ns1:sumResponse>\n"
+ "      <ns1:return>9</ns1:return>\n"
+ "    </ns1:sumResponse>\n"
+ "  </soapenv:Body>\n"
+ "</soapenv:Envelope>\n";

  @Test
  public void emptySource() throws Exception {
    String expectedError = "source variable resolves to null";
    msgCtxt.setVariable("message-content", signedSoapNoExpiry1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "not-message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, "stacktrace");
  }

  @Test
  public void missingAcceptableThumbprints() throws Exception {
    msgCtxt.setVariable("message.content", signedSoapNoExpiry1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("require-expiry", "false");
    // props.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, "accept-thumbprints resolves to an empty string");
  }

  @Test
  public void validResult() throws Exception {
    String method = "validResult() ";
    msgCtxt.setVariable("message.content", signedSoapNoExpiry1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("require-expiry", "false");
    props.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");

    Assert.assertTrue(isValid, method + "valid");
  }

  @Test
  public void requireExpiryFail() throws Exception {
    String method = "requireExpiryFail() ";
    msgCtxt.setVariable("message.content", signedSoapNoExpiry1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("throw-fault-on-invalid", "true");
    props.put("ignore-expiry", "true");
    // props.put("require-expiry", "false");
    props.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, "required element Timestamp/Expires is missing");

    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");
    Assert.assertFalse(isValid, method + "valid");
  }

  @Test
  public void emptyDoc() throws Exception {
    String method = "emptyDoc() ";
    msgCtxt.setVariable("message.content", emptyDocument);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    // props.put("require-expiry", "false");
    props.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, "lineNumber: 1; columnNumber: 1; Premature end of file.");

    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");
    Assert.assertFalse(isValid, method + "valid");
  }

  @Test
  public void requireExpiry() throws Exception {
    String method = "requireExpiry() ";
    msgCtxt.setVariable("message.content", signedSoapWithExpiry1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("ignore-expiry", "true");
    // props.put("require-expiry", "false");
    props.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");

    Object notice = msgCtxt.getVariable("wssec_notice");
    Assert.assertEquals(notice, "Timestamp/Expires is past");

    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");

    Assert.assertTrue(isValid, method + "valid");
  }

  @Test
  public void maxLifetime() throws Exception {
    String method = "maxLifetime() ";
    msgCtxt.setVariable("message.content", signedSoapWithExpiry1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("ignore-expiry", "true");
    props.put("max-lifetime", "3m");
    props.put("throw-fault-on-invalid", "true");
    // props.put("require-expiry", "false");
    props.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, "Lifetime of the document exceeds configured maximum");

    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");
    Assert.assertFalse(isValid, method + "valid");
  }

  @Test
  public void missingSecurityTokenReference() throws Exception {
    String method = "missingSecurityTokenReference() ";
    msgCtxt.setVariable("message.content", signedSoapMissingSecurityTokenReference);

    Map<String, String> props = new HashMap<String, String>();
    // props.put("debug", "true");
    props.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, "No suitable child element of KeyInfo");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNotNull(exception, method + "exception");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace"); // because debug = false
    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");

    Assert.assertFalse(isValid, method + "valid");
  }

  @Test
  public void subjectNameMismatch() throws Exception {
    String method = "subjectNameMismatch() ";
    msgCtxt.setVariable("message.content", signedSoapNoExpiry1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("require-expiry", "false");
    props.put("throw-fault-on-invalid", "true");
    props.put("source", "message.content");
    props.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d"); // match
    props.put("accept-subject-cns", "abc.example.com"); // name mismatch => expect invalid

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, "subject common name not accepted");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");

    Assert.assertFalse(isValid, method + "valid");
  }

  @Test
  public void thumbprintNotAccepted() throws Exception {
    String method = "thumbprintNotAccepted() ";
    msgCtxt.setVariable("message.content", signedSoapNoExpiry1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("require-expiry", "false");
    props.put("throw-fault-on-invalid", "true");
    props.put("source", "message.content");
    props.put("accept-thumbprints", "Xxxxxxxxxxxxxxxxxx"); // mismatch

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, "certificate thumbprint not accepted");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");

    Assert.assertFalse(isValid, method + "valid");
  }

  @Test
  public void viaRawCertificate() throws Exception {
    String method = "viaRawCertificate() ";
    msgCtxt.setVariable("message.content", signedSoapWithKeyInfoRawCert);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("require-expiry", "false");
    props.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");

    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");
    Assert.assertTrue(isValid, method + "valid");
  }

  @Test
  public void viaThumbprintAndExternalCert() throws Exception {
    String method = "viaThumbprintAndExternalCert() ";
    msgCtxt.setVariable("message.content", signedSoapWithKeyInfoThumbprint);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("ignore-expiry", "true");
    props.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
    props.put("certificate", "{my-certificate}");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");

    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");
    Assert.assertTrue(isValid, method + "valid");
  }

  @Test
  public void viaThumbprintAndExternalCert_Fail() throws Exception {
    String method = "viaThumbprintAndExternalCert_Fail() ";
    msgCtxt.setVariable("message.content", signedSoapWithKeyInfoThumbprint);
    msgCtxt.setVariable("my-certificate", pairs[1].certificate); // not the right cert

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("ignore-expiry", "true");
    props.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
    props.put("certificate", "{my-certificate}");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertEquals(errorOutput, "KeyInfo/SecurityTokenReference/KeyIdentifier thumbprint mismatch");

    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");
    Assert.assertFalse(isValid, method + "valid");
  }

  @Test
  public void viaIssuerAndSerial() throws Exception {
    String method = "viaIssuerAndSerial() ";
    msgCtxt.setVariable("message.content", signedSoapWithIssuerSerial);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("ignore-expiry", "true");
    props.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
    props.put("certificate", "{my-certificate}");
    props.put("source", "message.content");

    Validate callout = new Validate(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");

    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");
    Assert.assertTrue(isValid, method + "valid");
  }


  @Test
  public void roundTrip() throws Exception {
    String method = "roundTrip() ";
    msgCtxt.setVariable("message.content", soapGetContacts);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props1 = new HashMap<String, String>();
    props1.put("debug", "true");
    props1.put("source", "message.content");
    props1.put("private-key", "{my-private-key}");
    props1.put("certificate", "{my-certificate}");
    props1.put("key-identifier-type", "issuer_serial");
    props1.put("output-variable", "output");

    Sign callout1 = new Sign(props1);

    // execute and retrieve output
    ExecutionResult actualResult1 = callout1.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult1, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput1 = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput1, "errorOutput");

    String signedDocument = (String) msgCtxt.getVariable("output");

    // now, round-trip. Check that the signed document validates.
    msgCtxt.setVariable("signed-document", signedDocument);

    Map<String, String> props2 = new HashMap<String, String>();
    props2.put("debug", "true");
    //props2.put("accept-thumbprints", "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
    props2.put("require-expiry", "false");
    props2.put("certificate", "{my-certificate}");
    props2.put("source", "signed-document");

    Validate callout2 = new Validate(props2);

    // execute and retrieve output
    ExecutionResult actualResult2 = callout2.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult2, ExecutionResult.SUCCESS, "result not as expected");
    Object errorOutput2 = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput2, "errorOutput");

    Boolean isValid = (Boolean) msgCtxt.getVariable("wssec_valid");
    Assert.assertTrue(isValid, method + "valid");
  }
}
