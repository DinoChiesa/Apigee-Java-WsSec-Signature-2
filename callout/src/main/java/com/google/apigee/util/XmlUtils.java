// Copyright 2017-2020 Google LLC
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
package com.google.apigee.util;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class XmlUtils {

    private static DocumentBuilder getBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

        DocumentBuilder builder = factory.newDocumentBuilder();
        // prevent DTD entities from being resolved.
        builder.setEntityResolver(new EntityResolver() {
            @Override
            public InputSource resolveEntity(String publicId, String systemId)
                    throws SAXException, IOException {
                return new InputSource(new StringReader(""));
            }
        });

        return builder;
    }
    public static Document parseXml(InputStream in)
        throws IOException, SAXException, ParserConfigurationException {
        DocumentBuilder builder = getBuilder();
        InputStream bin = new BufferedInputStream(in);
        Document ret = builder.parse(new InputSource(bin));
        return ret;
    }
    public static Document parseXml(String s)
        throws IOException, SAXException, ParserConfigurationException {
        DocumentBuilder builder = getBuilder();
        InputSource is = new InputSource();
        is.setCharacterStream(new StringReader(s));
        Document ret = builder.parse(is);
        return ret;
    }

    public static String toString(Document doc) throws TransformerException {
        return XmlUtils.toString(doc, false);
    }

    public static String toString(Document doc, boolean pretty) throws TransformerException {
        DOMSource domSource = new DOMSource(doc);
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        if (pretty)
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.transform(domSource, result);
        return writer.toString();
    }

  public static Element getDirectChildElement(Element parent, String localName, String namespace) {
    if (parent == null) {
      return null;
    }
    for (Node currentChild = parent.getFirstChild();
         currentChild != null;
         currentChild = currentChild.getNextSibling()
         ) {
      if (Node.ELEMENT_NODE == currentChild.getNodeType()
          && localName.equals(currentChild.getLocalName())
          && namespace.equals(currentChild.getNamespaceURI())) {
        return (Element) currentChild;
      }
    }
    return null;
  }

  public static Element getReferencedElement(Document doc, String refUri) {
    if (refUri != null && refUri.startsWith("#")) {
      refUri = refUri.substring(1);
      Element referent = doc.getElementById(refUri);
      return referent;
    }
    return null;

  }

  // public static String toPrettyString(Document document, int indent) {
  //   try {
  //     // Remove whitespaces outside tags
  //     document.normalize();
  //     XPath xPath = XPathFactory.newInstance().newXPath();
  //     NodeList nodeList =
  //         (NodeList)
  //             xPath.evaluate("//text()[normalize-space()='']", document, XPathConstants.NODESET);
  //
  //     for (int i = 0; i < nodeList.getLength(); ++i) {
  //       Node node = nodeList.item(i);
  //       node.getParentNode().removeChild(node);
  //     }
  //
  //     // Setup pretty print options
  //     TransformerFactory transformerFactory = TransformerFactory.newInstance();
  //     transformerFactory.setAttribute("indent-number", indent);
  //     Transformer transformer = transformerFactory.newTransformer();
  //     transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
  //     transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
  //     transformer.setOutputProperty(OutputKeys.INDENT, "yes");
  //
  //     // Return pretty print xml string
  //     StringWriter stringWriter = new StringWriter();
  //     transformer.transform(new DOMSource(document), new StreamResult(stringWriter));
  //     return stringWriter.toString();
  //   } catch (Exception e) {
  //     throw new RuntimeException(e);
  //   }
  // }

  // public static Element getFirstChildElement(Element element) {
  //   for (Node currentChild = element.getFirstChild();
  //        currentChild != null;
  //        currentChild = currentChild.getNextSibling()) {
  //     if (currentChild instanceof Element) {
  //       return (Element) currentChild;
  //     }
  //   }
  //   return null;
  // }

  public static String asString(Node node) {
    StringWriter writer = new StringWriter();
    try {
      Transformer trans = TransformerFactory.newInstance().newTransformer();
      trans.setOutputProperty(OutputKeys.INDENT, "yes");
      trans.setOutputProperty(OutputKeys.VERSION, "1.0");
      if (!(node instanceof Document)) {
        trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
      }
      trans.transform(new DOMSource(node), new StreamResult(writer));
    } catch (final TransformerConfigurationException ex) {
      throw new IllegalStateException(ex);
    } catch (final TransformerException ex) {
      throw new IllegalArgumentException(ex);
    }
    return writer.toString();
  }
}
