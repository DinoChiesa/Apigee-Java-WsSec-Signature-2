// Constants.java
// ------------------------------------------------------------------
package com.google.apigee.xml;

public class Constants {
  public static final String X509_V3_TYPE =
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";

  public static final String THUMBPRINT_SHA1 =
      "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security1.1#ThumbprintSHA1";

  public static final String BASE64_BINARY =
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

  public static final String SIGNING_METHOD_RSA_SHA256 =
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  public static final String SIGNING_METHOD_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
}
