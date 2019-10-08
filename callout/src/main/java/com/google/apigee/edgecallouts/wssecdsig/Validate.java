// Copyright 2018-2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.edgecallouts.wssecdsig;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Map;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class Validate extends WssecCalloutBase implements Execution {

  public Validate(Map properties) {
    super(properties);
  }

  private static PublicKey readPublicKey(String publicKeyPemString)
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    PEMParser pr = new PEMParser(new StringReader(publicKeyPemString));
    Object o = pr.readObject();
    if (o instanceof SubjectPublicKeyInfo) {
      SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) o;
      RSAPublicKey pubKey = RSAPublicKey.getInstance(subjectPublicKeyInfo.parsePublicKey());

      PublicKey publicKey =
          KeyFactory.getInstance("RSA")
              .generatePublic(
                  new RSAPublicKeySpec(pubKey.getModulus(), pubKey.getPublicExponent()));

      return publicKey;
    }
    throw new IllegalStateException("Didn't find an RSA Public Key");
  }

  private PublicKey getPublicKey(MessageContext msgCtxt) throws Exception {
    String publicKeyPemString = getSimpleRequiredProperty("public-key", msgCtxt);
    publicKeyPemString = publicKeyPemString.trim();

    // clear any leading whitespace on each line
    publicKeyPemString = publicKeyPemString.replaceAll("([\\r|\\n] +)", "\n");
    return readPublicKey(publicKeyPemString);
  }

  private static boolean validate_RSA_SHA256(Document doc, PublicKey publicKey)
      throws MarshalException, XMLSignatureException {
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (nl.getLength() == 0) {
      throw new RuntimeException("Couldn't find 'Signature' element");
    }
    Element element = (Element) nl.item(0);
    KeySelector ks = KeySelector.singletonKeySelector(publicKey);
    DOMValidateContext vc = new DOMValidateContext(ks, element);
    XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
    XMLSignature signature = signatureFactory.unmarshalXMLSignature(vc);
    return signature.validate(vc);
  }

  public ExecutionResult execute(final MessageContext msgCtxt, final ExecutionContext execContext) {
    try {
      Document document = getDocument(msgCtxt);
      PublicKey publicKey = getPublicKey(msgCtxt);
      boolean isValid = validate_RSA_SHA256(document, publicKey);
      msgCtxt.setVariable(varName("valid"), isValid);
      return ExecutionResult.SUCCESS;
    } catch (IllegalStateException exc1) {
      setExceptionVariables(exc1, msgCtxt);
      return ExecutionResult.ABORT;
    } catch (Exception e) {
      String stacktrace = getStackTraceAsString(e);
      if (getDebug()) {
        System.out.println(stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      return ExecutionResult.ABORT;
    }
  }
}
