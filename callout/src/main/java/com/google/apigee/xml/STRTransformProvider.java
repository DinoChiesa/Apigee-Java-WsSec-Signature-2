// STRTransformProvider.java
// ------------------------------------------------------------------

package com.google.apigee.xml;

import java.security.Provider;

public class STRTransformProvider extends Provider {

    public STRTransformProvider() {
       super("STRTransform", 1.6, "Security Token Reference Transform Provider");
       put("TransformService." + STRTransform.TRANSFORM_URI,
           "com.google.apigee.xml.STRTransform" );
       put("TransformService." + STRTransform.TRANSFORM_URI + " MechanismType", "DOM");
   }
}
