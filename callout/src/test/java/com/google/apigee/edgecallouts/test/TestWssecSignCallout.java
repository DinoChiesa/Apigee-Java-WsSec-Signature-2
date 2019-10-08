package com.google.apigee.edgecallouts.test;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.edgecallouts.wssecdsig.Sign;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.util.HashMap;
import java.util.Map;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import mockit.Mock;
import mockit.MockUp;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class TestWssecSignCallout {

  static {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  MessageContext msgCtxt;
  InputStream messageContentStream;
  Message message;
  ExecutionContext exeCtxt;

  @BeforeMethod()
  public void beforeMethod() {

    msgCtxt =
        new MockUp<MessageContext>() {
          private Map variables;

          public void $init() {
            variables = new HashMap();
          }

          @Mock()
          public <T> T getVariable(final String name) {
            if (variables == null) {
              variables = new HashMap();
            }
            return (T) variables.get(name);
          }

          @Mock()
          public boolean setVariable(final String name, final Object value) {
            if (variables == null) {
              variables = new HashMap();
            }
            variables.put(name, value);
            return true;
          }

          @Mock()
          public boolean removeVariable(final String name) {
            if (variables == null) {
              variables = new HashMap();
            }
            if (variables.containsKey(name)) {
              variables.remove(name);
            }
            return true;
          }

          @Mock()
          public Message getMessage() {
            return message;
          }
        }.getMockInstance();

    exeCtxt = new MockUp<ExecutionContext>() {}.getMockInstance();

    message =
        new MockUp<Message>() {
          @Mock()
          public InputStream getContentAsStream() {
            // new ByteArrayInputStream(messageContent.getBytes(StandardCharsets.UTF_8));
            return messageContentStream;
          }
        }.getMockInstance();
  }

  private static final String privateKey1 =
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
          + "MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIe1dDIKI2EhwCAggA\n"
          + "MB0GCWCGSAFlAwQBAgQQijMNrkSU3jGJLHP90tc81ASCBNATKUMZxgfrCN67P3V6\n"
          + "/5iqKfoPcvmV+V1XJT9f/Y3YezMOvE9pAUtLv30N7HBcwadwbqsmfqYh7lVDOvpB\n"
          + "nyAayr5U0zZtfHS66XinZdtBc8UbMu2pb6DQ0pzrhG/tmo09QD7JDqs2Lq0Z88a4\n"
          + "2H5LbgAJMgpFwGVLPR/ZMmRe5zrsOjfmmVnt10hTarKVnjM/pc0S34TpnLlMKSjR\n"
          + "fIsqLFNAg9vZP2WHUChmGUNe9YaNZfe1r6S1TiPc5M0y62H996rYIR8FKxys6lxb\n"
          + "s0bFoYd0YWA50hDcXltmwyQPYBBRwUbRjLeQTUcR0W75bh34Ee/K9pqfYtQTf5Tw\n"
          + "+DiVv9FgDW9bIi30q1iovh7lboBUSWS2X4dfN1f/CDOFdeEm0Mi6yE/qqGDpjVrF\n"
          + "88xpmLnCy4WvKu97f4CLiL5fsVQu3yP9T6aldP+NOq4qXg96kpjwBjQDjCYRMpCi\n"
          + "Z8OHhoWa10EzRM8p5e4DiXco5YzVd5CpdxshKxT/sCvpHmWpVjzruANTXNQXXy6N\n"
          + "kWO+5PT9nSpb7+GOHruWrImkyytt6Yq53Rli6FCf22cgLxHaIN6mCbQuxb6InVxh\n"
          + "h1a7ccvbR2d7rk9FVbrfLSQ5vEWJnYFpoxWvrQGwKQHaYHbYfqH/oouaiN1vDrzu\n"
          + "NW0+y+lSYrMy+Rxv+vPD5EBt7aY1tj9sgrcWcHlSpkoyAttmWgmoF5TGF4A8M76r\n"
          + "+dzAdkkxqxGUP6prdkGvleWCwRnrmEXyKYILc2MtJxG45bD/XpSQKitkyRnXFF+J\n"
          + "MpdYCZES0NgFauPxVgnl4xkKjcpdV6e3HaJHatWY1/D6M1vIH0n/RT8uQhu/YpzF\n"
          + "hvsUsc+E6/jCN/P4mN6FlCugBzEouIseRhdXIL9qzQdSE1MmVzERlFNkNeqD+j+I\n"
          + "LvktK2s/VhBZxAf2yU9t4a92wQRaQyLPlsB/KFJ8tbGQGpgu1OqiJ4BcKlFBp2Jq\n"
          + "p4ivjcD+S4aKzMyQI9fMEyxOrHN0sfAHq2VBDS2QkcYWhe6qlckkDQJ7tWRhqzmi\n"
          + "k6LFGnjbA6RPnABJ9N2/JX4bEzlOeODiMXD81FLeHTlNUBgSNx8Itwm3DU6Jnv49\n"
          + "PqWICTMHWmXUkAwLbjydRBO6MVUQUNVpcM/dl5M/x0KPsghX7gXoXiPKIe9xrq6w\n"
          + "FcXZa2hED/9EJLLz6WvMtqX1BcrxA+wbueiTN8y+1GI6UkvTg42Iw//2t4qKwMv+\n"
          + "Q/jadrmxIgcyTe5GVxGUWmC336vW3bz2Vc7IEWDUcX0x+XLaw4ByKbKx2bti1mcN\n"
          + "zz/r2GZw1BtdWVCFQw2NfF4rLM5GCbrjF4XG5RB0Lbp1Q2XqXXRKJXR6kZuTgDgU\n"
          + "dFwGqhP1mwCGs9/Pg0AfGvqn+jcGipVevx/OFEiu+eK6VNYz4vAt5gU3sLyUwcpC\n"
          + "2vUN8Kh4TY4J4oJNeDibWU//qu35c+SoQQPC1L850ZCFsXoGg9TCGuhG97KlZxNw\n"
          + "i+CJHKTOWpPwLiPrVPtIp+Q6X8sRibLBdetXhq0P6Nh4mRew6iUg1DzClkK5/jFP\n"
          + "Tt5sUjnIV974hjP7F2e64scWXAIoEDYPdhhP/uLbxUmy0Cr9Jt8uUEGb+H7nWOUe\n"
          + "1MYSgvlF9eUm6e21FySl6H1kgw==\n"
          + "-----END ENCRYPTED PRIVATE KEY-----\n";

  private static final String privateKey2 =
      "-----BEGIN RSA PRIVATE KEY-----\n"
          + "Proc-Type: 4,ENCRYPTED\n"
          + "DEK-Info: DES-EDE3-CBC,63802B11A1FDFA29\n"
          + "\n"
          + "tGf3pCDVH00UpEmIB6YZxoJ7WcEwM1YIesjXMEpAmZUzwE9R6qu9J9c2idfMIy5z\n"
          + "0vlQnV3dU3DUuTXeaJZT/Gijs9jc8X1yTNDEKhNVX3NI/kDbC9xC+T20FS/LdSK7\n"
          + "kz18o3s9YutwSqc3RZeYb0ECR5uNv0ZQRv9GPQBVeJbfFS9GyXeE6UHgg4e9c0hW\n"
          + "3Ru9Z7XTtsPhhBdoV1rg8HvCsUADQMhOFTzlCaAD/bO6yhTeaeFIwXcAjK8Bdg72\n"
          + "mMUTgjZwfOyhrCB36Rfuv64MaZZfPqITM54Ha5exWbqjGbU+B5FkKppTV54eHen7\n"
          + "2mkCCUckGT9VLfMrXjZmBlmUSSgLNJguBwH5rIbEze2NcMJwX6oNoXVIC6j/Qt9D\n"
          + "VL7t1js5y4Xg/L2DbOfOrN4FAX1bOaaulS1wFmcyGTR5bYOTFRYqA8gfGP36wWdi\n"
          + "o4mEEgpdGuRsGvkI7svnQHFgKMvRgCG+aWg9PGeacpBHtjmv2A+KNiL0Am1x2bOM\n"
          + "B55kZCcHd/81/4lz/iKLG2dEpN2fqw5qxP0/UMqeehemUHBiX2sxPV1yIStAppno\n"
          + "dkZG9G0prnfCEHz47msj1gN4J4fyX2WxWyRKIUP+hNwuw5Sh9slc4HGyV/StfRsJ\n"
          + "4fjJaMmxDAc112JCbRCoxyxWVIcEEo35wBOTSEzlYF2zj179XnzD2519vc+QGpqc\n"
          + "q7/j/9dr0VLt78rrjCnH2DCA+K24zQluyKI2bkkNVeS+dqfHrK2b11guQiPAhLWd\n"
          + "4MAtt+zz0VxMyE3MExZwwFAs8Wxb5kG9Wam6FXdZiRNAFtNZ9Ab4fuDBLObHXlbU\n"
          + "rHXRHZmUbmCoW8B7cd6NlMrJQCsxSPyN9rhuyjEueB2UuMX4IXOZcghT8Ej0KMP+\n"
          + "OF4gYdL9loznsAmQspLG3NJESYQ6tZax6XayibWQGdVj2QwT3YZ7j2fRMVv8OQy6\n"
          + "TWMVMRXqVySAhB9KYNqfEYA+jw2aFWnwkKkcmHSadsVNs74GKwpvXwT48tmBjBAb\n"
          + "xbycgSV7ZBIzbXUMbBpZ/59h8eVLMmKVB9UmV6nQK2sYnhJ6wz0h3WjyQR0YJ9yJ\n"
          + "1OJTiAnvVAMJcs0Nju9Bf6qYOMvm8KWResVAmqfdENyiU9fuFR4FwbSVbPuebC/u\n"
          + "Y82c1hlNg/3gl5b7aUqNuoH1UeNuBf/C4HrLu7yhKuyVWAK7egRh+LhcYRYZWCWg\n"
          + "EPV89Rez36j6np4Lt4xNiyF92mHkld7+uG5Uw7+EGJWM9R/E7vY1w3A/i7BsIjNt\n"
          + "qBWFJP9Bq89kdl0wCKrKCbKHPkGb+8yy8ivu3Y9q+DtcnZXmOxxg4C43biyUeFVw\n"
          + "PWvdQwjEmliRzlsZEh65EDu9Od+VHPmKSU9bxTWYjHzpMjadEV/yQA312vdtdiSU\n"
          + "KA2BDCmNQFiTbcFsulxRhGxgHcexuYvuoLQNGfS6Qd85Leu0LJyn258eE0oRPxgi\n"
          + "77vm5V4RuEKiGr0+7cBcswZ4mDd+OJQYCYHGoDbpYFO4Rgy7WakCLI6I32E373BX\n"
          + "WoAnf4VfajzL/IDHUQV8TuM8YB0X2WdyxxobXb8BepqgDe3Aq83JZheE0HxoPEmR\n"
          + "-----END RSA PRIVATE KEY-----\n";

  private static final String privateKey3 =
"-----BEGIN PRIVATE KEY-----\n"
+"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCokDY3Bd6pdpVo\n"
+"c7SaQoOlN2E8KH/zSAfY66fgMk5iNiC90xEnzfEHofCbzT1Pn3euRf0/A6NQNDuQ\n"
+"m8fRotqrFv4WutMNMVxdlclnrl1xr2VgBHGAQDBqw8iS8F2vSc/ZbZVCA8q2TBK1\n"
+"mKcyImH8lKVcLPtQsMZWpbwXKSUZpUiTGteEeyMf6GEnwqn7OMWx92xOQZtqpeP+\n"
+"p7F4dQFwXoZsd7vGFouiP8/bgPuYUcHe5fHi83eiE/5mJPXLlfx8ItW7lJIL68MU\n"
+"dHZnkjbrJOVw1HAq3biU3KkawTMzkpkgsmUSvcGcADWqRxJfvBlAMendc4ckdpHq\n"
+"XFqu9iWZAgMBAAECggEBAICZXTNHQCOLe9svgxa5LhRLFty9jTg+uPXue6oY1yIo\n"
+"Z3xK3ei/PmbzTkyfHWp0n+sOLHH5xYu3/cWKg7zVAPzMUtdmewOyp+QiFYELTvEf\n"
+"vjityyXsUsPxUEGCLgdASdl4uAmgOPQxP4jZyJ0ADD+V7D5Rdv6NjxOl58THuC1C\n"
+"ZUq5wyJpm9U+MeUWCYJHWTh3Nj5BVdokYA4G0SeAMuQsGAWXQTR1VTrFEPEouX8a\n"
+"mCTMYHQP5mfrPD+gAYKGPrjwVyZZI8CnqfxlNhkSt3etuXbHjHHzPb6mPNjOJKgU\n"
+"5xS5I737wKR1kF0NM14WTeCvSzFNAgo9E9yfVTxIXjECgYEA3rgIgUoA3lk8lsJ/\n"
+"uOjYRMyDgiYVJ3GMyZ7ll+LqkWRWhEx69NiNeMED32oqKMxBvvM+Q/wgoC5rHJTM\n"
+"Nd1jbzlqGscJqlW66x8r5bXY9iwhJhiNpNlj+FIPaXktivVG741qTLWnsM5Rrv8L\n"
+"7leZjEsWNJWAw90FhJTaZ7A3dp0CgYEAwcB+LqjNQQdmNSyBaLTb6Shr6IgOCf/1\n"
+"NHlqatFsdmy8F2+5+ePExpb7HCbiY5Gi96JBczZ5qEK/yzAIC8WWCLxvtPn/x/vE\n"
+"ByO7ZXa4dN80KENta0sWWdV3mNFoqU1TR8Cno5a8a3A705CFjI6kSLDxhOSeBfuF\n"
+"JzErU/oXvC0CgYAF6AeBtj6zptYugVX1x2cE3A+Ywf3Jn/9F0YrxLjleRbTtqUGR\n"
+"gLSvwR6jLCOWFWSg9b5u+x66YMDCb0fDHe3nIzSnJSQiekeMuLTnUJ1CWgU/B2Oq\n"
+"PYGjMjnqaCZHCx4oeC2bfy3FSJNt+qGMXpJZ4BvkpRpXF2NwEqqAGXI/GQKBgDam\n"
+"y3Dx4GO1aJkbIq2cRmOwKTAAIKWlc08H6IKU7BlDdpLNyxG3s6uortA0D6uyStu7\n"
+"AucyuIJDwcHYnIxlgXqZXJEZ65JHa/XvmE54fHNK+nVY/6ZCGd3hHskWWIVY8GLO\n"
+"7vpv7FoJ4HY+z8zj92chsh6gNgrN9bMmZWhcpRFJAoGAMih1rmZx8PBwrnkMvwVB\n"
+"05Ar+LdS/CqG9egQJxtRSIzfdyc9CrZ6b7Sj+VWjieT/o78ODalbXQETia6bYv5b\n"
+"KWHu/XSeFDzGfCsZiGWECY0rpEKjvI8OBYljTKmB/14Iz51m8jgZRvTaoauUUpZi\n"
+"w+4PGMrpoKCGFBE4ucT7AvY=\n"
    +"-----END PRIVATE KEY-----\n";

  private static final String certificate3 =
"-----BEGIN CERTIFICATE-----\n"
+"MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMC\n"
+"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYD\n"
+"VQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdv\n"
+"b2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEw\n"
+"MDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UE\n"
+"CAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2ds\n"
+"ZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEe\n"
+"MBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEF\n"
+"AAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYg\n"
+"vdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9l\n"
+"YARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVI\n"
+"kxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB\n"
+"3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZ\n"
+"ILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEB\n"
+"BQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl3\n"
+"6iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZL\n"
+"klpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMB\n"
+"tqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4Wj\n"
+"ETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIR\n"
+"eK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib\n"
    +"-----END CERTIFICATE-----\n";

  private static final String privateKey4 =
      "-----BEGIN PRIVATE KEY-----\n"
          + "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC6fOeMaBe11Axe\n"
          + "4L6i0dTpkh+1ueBUYdgihFUyYPkYGOa4vaeuZSYe6EGhEO+DSksydfi7CCUuk4d9\n"
          + "nFGeDsb01PWeA95ZCEZMfbU0b1USZlRyKdcAR8j4wewP9d5N0e+5GDzA+KnmXKXH\n"
          + "FKNhSJqH5onAQUFolwQ0zy+dDWVMdh3m7mnQemTIofOBPU2IeTXsaYczwA3vZqPk\n"
          + "i8/iYP1/6AuoNyx2yhOgmvUr9friVInm7hKKFRhnP04KIRUC+wEmroIet4Naf+XC\n"
          + "5CCcVGU2nzS6fjjLeE7PTaCCv+XVGMmTREkvOF35kqy1xRov4dWFekilraRQzQRR\n"
          + "l/Tnt/dNAgMBAAECggEARyiH9fR2L6R0//MD6v7kHifqv53ocmpPXYRfOfT0t3Qw\n"
          + "/Ycop4vjCuIWwM3EhrVfkiafvUYzYd1bUtvF7Oi4lA16l0vkmNZmdKN29EYTEQ1I\n"
          + "5bL/XhUGI51jZQetRsZ3kYolDIEV21e4zgka+nEIvhiCsYB04+LT8Q6pnWTSJWU5\n"
          + "wrMKCJldDlsM65R4gWSvfU6YawX7R9N/gWDFDothJ5wPaIjd9u6m0LPgqJjJJQAw\n"
          + "F/hSkQe2owQRA7ZcibhQMTD+GkPWY8J/3x7PzhupCChVrQ7ISzhN0N+LWfoXUlOh\n"
          + "1yh4TtadP+n2yexvArWJRPphSEkTE1pc+kkHHR9xYQKBgQDkodIcOLW3cR742yH0\n"
          + "wIsVfpPy7O6AcjcMj+wY1/J+sFrTfyC/lMD94p7FDRBi5AoL90efupj5TkoZqFjG\n"
          + "XJH9VapDn+1IwfMuoJIHZMWpJP/4aedfvoCn9/ey66U0FEB5ExZQuQSOM+F47MS+\n"
          + "Y3j1vEDPbOmCMYJP0gle7YzYhQKBgQDQz577m3rz62Vr8m5Owp160BGnTRb/kDgQ\n"
          + "aAp5PwaKU9/njrV0Ptlpxm8TXBcC0et66iDMFb1LYteedh6qRYRrrWEU6M5rXqZK\n"
          + "n9TJWQSag2yqdlwNad+dVDw4aHrWpMZ1jRCgS99lMsGlayKFRIQv4ucflB5hUmlc\n"
          + "pZPf1itCKQKBgQCcBwcxtU3l27AsWreopUIFsDVdgm4dgFSrIQkZxz25UbcaQNbj\n"
          + "h6vRV7fMeGbnZgKpOd9KVXiSIuiU6/txm7kRr0WcEudHUP0ZpAEkRJRUI2kAaZ26\n"
          + "DHMWrjX/h6tdiDibp/gBrNI8DZHhCYwW9iGVahy8sfIFpK3utUMp4mnNVQKBgQCk\n"
          + "KDUyVL9Kd2rafFKf9Hvdiyn1vrMv4u9QZpqlSxkXMm06G4UniClf8LJuI92rR+C6\n"
          + "VsnF5+lTFLeySeY9sj0ycbF6wLNW0aglzpV4XVUzK9MIB9jCatNzWj+lkO3RROUI\n"
          + "kQfbHQrZAhgetaUD5COPifBtcQKZPDK8tScVt8d2UQKBgQC2+kFWAfL/WPvOpNV6\n"
          + "3wbcgoDh4PZPNgdnAqWiKRmFhHA02xvJZAmrRp3xo13w7zwHOxpMrOgTiyxTRm9a\n"
          + "O0nD18snZqHQfGudOw/OP/Ow9oCXg3ohytwce65MYC5ZstbaxUdk9+qhEOdX35ZP\n"
          + "qVEgJrIayuijmHBXXYZG3NjV1w==\n"
          + "-----END PRIVATE KEY-----\n";

  private static final String simpleSoap1 =
      "<soapenv:Envelope xmlns:ns1='http://ws.example.com/' xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'>"
          + "  <soapenv:Body>"
          + "    <ns1:sumResponse>"
          + "      <ns1:return>9</ns1:return>"
          + "    </ns1:sumResponse>"
          + "  </soapenv:Body>"
          + "</soapenv:Envelope>";

  private static Document docFromStream(InputStream inputStream)
      throws IOException, ParserConfigurationException, SAXException {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder().parse(inputStream);
    return doc;
  }

  @Test
  public void emptySource() throws Exception {
    String method = "emptySource() ";
    String expectedError = "source variable resolves to null";
    msgCtxt.setVariable("message-content", simpleSoap1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "not-message.content");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void missingPrivateKey() throws Exception {
    String method = "missingPrivateKey() ";
    String expectedError = "private-key resolves to an empty string";

    msgCtxt.setVariable("message.content", simpleSoap1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("source", "message.content");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNotNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    // System.out.printf("expected error: %s\n", errorOutput);
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
    System.out.println("=========================================================");
  }

  @Test
  public void validResult1() throws Exception {
    String method = "validResult1() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", privateKey1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // SignatureMethod (default)
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureMethod element");
    Element element = (Element) nl.item(0);
    String signatureMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(signatureMethodAlgorithm, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    element = (Element) nl.item(0);
    String canonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(canonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 2, method + "Reference element");

    // DigestMethod
    for (int i = 0; i < nl.getLength(); i++) {
      element = (Element) nl.item(i);
      NodeList digestMethodNodes =
          element.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestMethod");
      Assert.assertEquals(digestMethodNodes.getLength(), 1, method + "DigestMethod element");
      element = (Element) digestMethodNodes.item(0);
      String digestAlg = element.getAttribute("Algorithm");
      Assert.assertEquals(digestAlg, "http://www.w3.org/2000/09/xmldsig#sha1");
    }

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");

    System.out.println("=========================================================");
  }

  @Test
  public void signSha256() throws Exception {
    String method = "validResult1() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", privateKey1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("signing-method", "rsa-sha256");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // SignatureMethod (sha256)
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureMethod element");
    Element element = (Element) nl.item(0);
    String signatureMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(
        signatureMethodAlgorithm, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    element = (Element) nl.item(0);
    String canonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(canonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 2, method + "Reference element");

    // DigestMethod
    for (int i = 0; i < nl.getLength(); i++) {
      element = (Element) nl.item(i);
      NodeList digestMethodNodes =
          element.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestMethod");
      Assert.assertEquals(digestMethodNodes.getLength(), 1, method + "DigestMethod element");
      element = (Element) digestMethodNodes.item(0);
      String digestAlg = element.getAttribute("Algorithm");
      Assert.assertEquals(digestAlg, "http://www.w3.org/2000/09/xmldsig#sha1");
    }

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");

    System.out.println("=========================================================");
  }

  @Test
  public void digestSha256() throws Exception {
    String method = "validResult1() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", privateKey1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("digest-method", "sha256");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // SignatureMethod (default)
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureMethod element");
    Element element = (Element) nl.item(0);
    String signatureMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(signatureMethodAlgorithm, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    element = (Element) nl.item(0);
    String canonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(canonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 2, method + "Reference element");

    // DigestMethod
    for (int i = 0; i < nl.getLength(); i++) {
      element = (Element) nl.item(i);
      NodeList digestMethodNodes =
          element.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestMethod");
      Assert.assertEquals(digestMethodNodes.getLength(), 1, method + "DigestMethod element");
      element = (Element) digestMethodNodes.item(0);
      String digestAlg = element.getAttribute("Algorithm");
      Assert.assertEquals(digestAlg, "http://www.w3.org/2001/04/xmlenc#sha256");
    }

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");

    System.out.println("=========================================================");
  }

  @Test
  public void signOnlyTimestamp() throws Exception {
    String method = "signOnlyTimestamp() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", privateKey1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("elements-to-sign", "timestamp");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    Element element = (Element) nl.item(0);
    String CanonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(CanonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 1, method + "Reference element");
    Element reference = (Element) nl.item(0);
    String referenceUri = reference.getAttribute("URI");
    Assert.assertTrue(referenceUri.startsWith("#Timestamp"));

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");

    System.out.println("=========================================================");
  }

  @Test
  public void signOnlyBody() throws Exception {
    String method = "signOnlyBody() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", privateKey1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("elements-to-sign", "body");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));

    // signature
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");

    // c14n
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod");
    Assert.assertEquals(nl.getLength(), 1, method + "CanonicalizationMethod element");
    Element element = (Element) nl.item(0);
    String CanonicalizationMethodAlgorithm = element.getAttribute("Algorithm");
    Assert.assertEquals(CanonicalizationMethodAlgorithm, "http://www.w3.org/2001/10/xml-exc-c14n#");

    // Reference
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
    Assert.assertEquals(nl.getLength(), 1, method + "Reference element");
    Element reference = (Element) nl.item(0);
    String referenceUri = reference.getAttribute("URI");
    Assert.assertTrue(referenceUri.startsWith("#Body"));

    // SignatureValue
    nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue");
    Assert.assertEquals(nl.getLength(), 1, method + "SignatureValue element");

    System.out.println("=========================================================");
  }

  @Test
  public void test_ValidWithExpiry() throws Exception {
    String method = "test_ValidWithExpiry() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", privateKey1);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", minutesExpiry + "m");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    // System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");
    nl =
        doc.getElementsByTagNameNS(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
            "Timestamp");
    Assert.assertEquals(nl.getLength(), 1, method + "Timestamp element");
    nl =
        doc.getElementsByTagNameNS(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
            "Expires");
    Assert.assertEquals(nl.getLength(), 1, method + "Expires element");
    String expiryString = nl.item(0).getTextContent();
    // System.out.printf("expiry: %s\n", expiryString);
    Assert.assertNotNull(expiryString, method + "expiryString");
    TemporalAccessor creationAccessor = DateTimeFormatter.ISO_INSTANT.parse(expiryString);
    Instant expiry = Instant.from(creationAccessor);
    Instant now = Instant.now();
    long minutesTilExpiry = now.until(expiry, ChronoUnit.MINUTES);
    Assert.assertEquals(minutesTilExpiry, (long) (minutesExpiry - 1)); // rounding down

    System.out.println("=========================================================");
  }

  @Test
  public void oldFormatPrivateKeyEncrypted() throws Exception {
    String method = "oldFormatPrivateKeyEncrypted() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", privateKey2);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");
    System.out.println("=========================================================");
  }

  @Test
  public void oldFormatPrivateKeyEncryptedNoPassword() throws Exception {
    String method = "oldFormatPrivateKeyEncrypted() ";
    String expectedException = "org.bouncycastle.openssl.PEMException: exception processing key pair: password empty";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", privateKey2);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    // props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertEquals(exception, expectedException, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertEquals(errorOutput, "password empty", "errorOutput");
    System.out.println("=========================================================");
  }

  @Test
  public void withCertificate() throws Exception {
    String method = "withCertificate() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", privateKey3);
    msgCtxt.setVariable("my-certificate", certificate3);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    // props.put("private-key-password", "");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.SUCCESS, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNull(errorOutput, "errorOutput");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");

    String output = (String) msgCtxt.getVariable("output");
    System.out.printf("** Output:\n" + output + "\n");

    Document doc = docFromStream(new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)));
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Assert.assertEquals(nl.getLength(), 1, method + "Signature element");
    System.out.println("=========================================================");
  }

  @Test
  public void withCertificateMismatch() throws Exception {
    String method = "withCertificateMismatch() ";
    String expectedError = "public key mismatch. The public key contained in the certificate does not match the private key.";
      String expectedException = "java.security.KeyException: " + expectedError;
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", privateKey4);
    msgCtxt.setVariable("my-certificate", certificate3);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertEquals(exception, expectedException, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertEquals(errorOutput, expectedError, "errorOutput");
    System.out.println("=========================================================");
  }
}
