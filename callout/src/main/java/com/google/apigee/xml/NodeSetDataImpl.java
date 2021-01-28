package com.google.apigee.xml;

import java.util.Iterator;
import javax.xml.crypto.NodeSetData;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.traversal.DocumentTraversal;
import org.w3c.dom.traversal.NodeFilter;
import org.w3c.dom.traversal.NodeIterator;

public class NodeSetDataImpl implements NodeSetData, Iterator {
  private Node ivNode;
  private NodeFilter ivNodeFilter;
  private Document ivDocument;
  private DocumentTraversal ivDocumentTraversal;
  private NodeIterator ivNodeIterator;
  private Node ivNextNode;

  public NodeSetDataImpl(Node pNode, NodeFilter pNodeFilter) throws Exception {
    ivNode = pNode;
    ivNodeFilter = pNodeFilter;

    if (ivNode instanceof Document) {
      ivDocument = (Document) ivNode;
    } else {
      ivDocument = ivNode.getOwnerDocument();
    }

    ivDocumentTraversal = (DocumentTraversal) ivDocument;
  }

  private NodeSetDataImpl(NodeIterator pNodeIterator) {
    ivNodeIterator = pNodeIterator;
  }

  public Iterator iterator() {
    NodeIterator nodeIterator =
        ivDocumentTraversal.createNodeIterator(ivNode, NodeFilter.SHOW_ALL, ivNodeFilter, false);
    return new NodeSetDataImpl(nodeIterator);
  }

  private Node checkNextNode() {
    if (ivNextNode == null && ivNodeIterator != null) {
      ivNextNode = ivNodeIterator.nextNode();
      if (ivNextNode == null) {
        ivNodeIterator.detach();
        ivNodeIterator = null;
      }
    }
    return ivNextNode;
  }

  private Node consumeNextNode() {
    Node nextNode = checkNextNode();
    ivNextNode = null;
    return nextNode;
  }

  public boolean hasNext() {
    return checkNextNode() != null;
  }

  public Node next() {
    return consumeNextNode();
  }

  public void remove() {
    throw new UnsupportedOperationException("Removing nodes is not supported.");
  }

  public static NodeFilter getRootNodeFilter() {
    return new NodeFilter() {
      public short acceptNode(Node pNode) {
        if (pNode instanceof Element && pNode.getParentNode() instanceof Document) {
          return NodeFilter.FILTER_SKIP;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    };
  }
}
