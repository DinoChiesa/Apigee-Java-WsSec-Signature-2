/**
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.apigee.xml;

import com.google.apigee.util.XmlUtils;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.Iterator;
import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import org.apache.xml.security.c14n.Canonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class STRTransform extends TransformService {

  static {
    org.apache.xml.security.Init.init();
  }

  private static final Logger logger = LoggerFactory.getLogger(STRTransform.class);

  public static final String TRANSFORM_URI =
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform";

  public static final String TRANSFORM_WS_DOC_INFO = "transform_ws_doc_info";

  private TransformParameterSpec params;

  private Element transformElement;

  public final AlgorithmParameterSpec getParameterSpec() {
    return params;
  }

  public void init(TransformParameterSpec params) throws InvalidAlgorithmParameterException {
    this.params = params;
  }

  public void init(XMLStructure parent, XMLCryptoContext context)
      throws InvalidAlgorithmParameterException {
    logger.debug("init()");
    if (context != null && !(context instanceof DOMCryptoContext)) {
      throw new ClassCastException("context must be of type DOMCryptoContext");
    }
    if (!(parent instanceof javax.xml.crypto.dom.DOMStructure)) {
      throw new ClassCastException("parent must be of type DOMStructure");
    }
    transformElement = (Element) ((javax.xml.crypto.dom.DOMStructure) parent).getNode();
    logger.debug("init() element: {}", XmlUtils.asString(transformElement));
  }

  public void marshalParams(XMLStructure parent, XMLCryptoContext context) throws MarshalException {
    logger.debug("marshalParams()");
    if (context != null && !(context instanceof DOMCryptoContext)) {
      throw new ClassCastException("context must be of type DOMCryptoContext");
    }
    if (!(parent instanceof javax.xml.crypto.dom.DOMStructure)) {
      throw new ClassCastException("parent must be of type DOMStructure");
    }
    Element transformElement2 = (Element) ((javax.xml.crypto.dom.DOMStructure) parent).getNode();
    appendChild(transformElement2, transformElement);
    transformElement = transformElement2;
  }

  public Data transform(Data data, XMLCryptoContext xc) throws TransformException {
    logger.debug("transform()");
    if (data == null) {
      throw new NullPointerException("data must not be null");
    }
    return transformIt(data, xc, null);
  }

  public Data transform(Data data, XMLCryptoContext xc, OutputStream os) throws TransformException {
    logger.debug("transform()");
    if (data == null) {
      throw new NullPointerException("data must not be null");
    }
    if (os == null) {
      throw new NullPointerException("output stream must not be null");
    }
    return transformIt(data, xc, os);
  }

  private Data transformIt(Data data, XMLCryptoContext xc, OutputStream os)
      throws TransformException {
    logger.debug("transformIt()");
    String canonAlgo = null;
    Element transformParams =
        XmlUtils.getDirectChildElement(
            transformElement, "TransformationParameters", Namespaces.WSSEC);
    if (transformParams != null) {
      Element canonElem =
          XmlUtils.getDirectChildElement(
              transformParams, "CanonicalizationMethod", Namespaces.XMLDSIG);
      canonAlgo = canonElem.getAttributeNS(null, "Algorithm");
    }

    try {
      //
      // Get the input (node) to transform.
      //
      Element str = null;
      if (data instanceof NodeSetData) {
        NodeSetData nodeSetData = (NodeSetData) data;
        Iterator<?> iterator = nodeSetData.iterator();
        while (iterator.hasNext()) {
          Node node = (Node) iterator.next();
          if (node instanceof Element && "SecurityTokenReference".equals(node.getLocalName())) {
            str = (Element) node;
            break;
          }
        }
      } else {
        throw new UnsupportedOperationException("data is not NodeSetData");
      }
      if (str == null) {
        throw new TransformException("No SecurityTokenReference found");
      }

      Document doc = str.getOwnerDocument();
      Element reference = XmlUtils.getDirectChildElement(str, "Reference", Namespaces.WSSEC);
      String uri = reference.getAttribute("URI");
      if (uri == null) {
        throw new TransformException("Could not find URI on STR/Reference");
      }
      logger.debug(String.format("found URI [%s]", uri));
      System.out.printf("\n** found URI: %s\n", uri);
      Element dereferencedToken = XmlUtils.getReferencedElement(doc, uri);

      if (dereferencedToken == null) {
        throw new TransformException(String.format("Could not de-reference element [%s]", uri));
      }

      System.out.printf("** referenced element:\n%s\n", XmlUtils.asString(dereferencedToken));

      Element sigReference = (Element) (transformElement.getParentNode().getParentNode());
      Element digestValue =
          XmlUtils.getDirectChildElement(sigReference, "DigestValue", Namespaces.XMLDSIG);
      System.out.printf("** expected digest value: %s\n", digestValue.getTextContent());

      // // Make sure we are adding the default namespace if it is necessary to do so.
      // boolean wantDefaultNs =
      //     (dereferencedToken.getLocalName().equals("BinarySecurityToken")
      //         || dereferencedToken.getAttributeNS(null, "EncodingType") != null
      //         || dereferencedToken.getAttributeNS(null, "ValueType") != null);

      //
      // C14n with specified algorithm. According to WSS Specification.
      //

      Canonicalizer canonicalizer = Canonicalizer.getInstance(canonAlgo);
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      canonicalizer.canonicalizeSubtree(dereferencedToken, "#default", true, baos);

      if (os != null) {
        byte[] b = baos.toByteArray();
        os.write(b, 0, b.length);
        String referredData = new String(b);
        String sha1Digest =
            Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA1").digest(b));
        System.out.printf("\n** transformed (c14n) data:\n%s\n", referredData);
        System.out.printf("\n** digest of same: %s\n", sha1Digest);
        return null;
      }

      logger.debug("transformIt() outputStream is null");

      // return transformedData;
      return null;

    } catch (Exception ex) {
      throw new TransformException(ex);
    }
  }

  public final boolean isFeatureSupported(String feature) {
    if (feature == null) {
      throw new NullPointerException();
    } else {
      return false;
    }
  }

  private static void appendChild(Node parent, Node child) {
    Document ownerDoc = null;
    if (parent.getNodeType() == Node.DOCUMENT_NODE) {
      ownerDoc = (Document) parent;
    } else {
      ownerDoc = parent.getOwnerDocument();
    }
    if (child.getOwnerDocument() != ownerDoc) {
      parent.appendChild(ownerDoc.importNode(child, true));
    } else {
      parent.appendChild(child);
    }
  }
}
