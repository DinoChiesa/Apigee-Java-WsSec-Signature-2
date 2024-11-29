package com.google.apigee.xml;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

public class Namespaces {
  public static final String WSA = "http://www.w3.org/2005/08/addressing";
  public static final String WSU =
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
  public static final String SOAP1_1 = "http://schemas.xmlsoap.org/soap/envelope/";
  public static final String SOAP1_2 = "http://www.w3.org/2003/05/soap-envelope";
  public static final String WSSEC =
      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
  public static final String WSSEC_11 =
      "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
  public static final String XMLNS = "http://www.w3.org/2000/xmlns/";
  public static final String XMLDSIG = "http://www.w3.org/2000/09/xmldsig#";

  public static final Map<String, String> defaultPrefixes;
  public static final Map<String, String> defaultNamespaces;

  static {
    Map<String, String> map1 = new HashMap<String, String>();
    map1.put(WSA, "wsa");
    map1.put(WSU, "wsu");
    map1.put(SOAP1_1, "soap1.1");
    map1.put(SOAP1_2, "soap1.2");
    map1.put(WSSEC, "wssec");
    map1.put(WSSEC_11, "wssec1.1");
    map1.put(XMLDSIG, "ds");

    defaultPrefixes = Collections.synchronizedMap(map1);

    Map<String, String> map2 = new HashMap<String, String>();
    map2.put("wsa", WSA);
    map2.put("wsu", WSU);
    map2.put("soap1.1", SOAP1_1);
    map2.put("soap1.2", SOAP1_2);
    map2.put("wssec", WSSEC);
    map2.put("wssec1.1", WSSEC_11);
    map2.put("ds", XMLDSIG);

    defaultNamespaces = Collections.synchronizedMap(map2);
  }

  private static void fillExistingNamespaces(Map<String, String> known, Element element) {
    NamedNodeMap attributes = element.getAttributes();
    if (attributes != null) {
      for (int i = 0; i < attributes.getLength(); i++) {
        Node node = attributes.item(i);
        if (node.getNodeType() == Node.ATTRIBUTE_NODE) {
          String name = node.getNodeName();
          if (name.startsWith("xmlns:")) {
            String value = node.getNodeValue();
            String prefix = name.substring(6);
            if (!known.containsValue(prefix)) {
              known.put(value, prefix);
            }
          }
        }
      }
    }
    Node parent = element.getParentNode();
    if (parent != null && parent instanceof Element) {
      fillExistingNamespaces(known, (Element) parent);
    }
  }

  public static Map<String, String> getExistingNamespaces(Element element) {
    Map<String, String> knownNamespaces = new HashMap<String, String>();
    fillExistingNamespaces(knownNamespaces, element);
    return knownNamespaces; // key:namespace, value:prefix
  }
}
