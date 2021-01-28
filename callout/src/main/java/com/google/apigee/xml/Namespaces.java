package com.google.apigee.xml;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

public class Namespaces {
  public static final String WSU =
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
  public static final String SOAP1_1 = "http://schemas.xmlsoap.org/soap/envelope/";
  public static final String SOAP1_2 = "http://www.w3.org/2003/05/soap-envelope";
  public static final String WSSEC =
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
  public static final String XMLNS = "http://www.w3.org/2000/xmlns/";
  public static final String XMLDSIG = "http://www.w3.org/2000/09/xmldsig#";

  public static final Map<String, String> defaultPrefixes;

  static {
    HashMap map1 = new HashMap<String, String>();
    map1.put(WSU, "wsu");
    map1.put(SOAP1_1, "soap1.1");
    map1.put(SOAP1_2, "soap1.2");
    map1.put(WSSEC, "wssec");
    map1.put(XMLDSIG, "ds");

    defaultPrefixes = Collections.synchronizedMap(map1);
  }

  public static Map<String, String> getExistingNamespaces(Element element) {
    Map<String, String> knownNamespaces = new HashMap<String, String>();
    NamedNodeMap attributes = element.getAttributes();
    if (attributes != null) {
      for (int i = 0; i < attributes.getLength(); i++) {
        Node node = attributes.item(i);
        if (node.getNodeType() == Node.ATTRIBUTE_NODE) {
          String name = node.getNodeName();
          if (name.startsWith("xmlns:")) {
            String value = node.getNodeValue();
            knownNamespaces.put(value, name.substring(6));
          }
        }
      }
    }
    return Collections.unmodifiableMap(knownNamespaces); // key:namespace, value:prefix
  }
}
