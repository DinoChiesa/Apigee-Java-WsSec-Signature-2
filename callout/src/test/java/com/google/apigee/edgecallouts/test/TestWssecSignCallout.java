package com.google.apigee.edgecallouts.test;

import com.apigee.flow.execution.ExecutionResult;
import com.google.apigee.edgecallouts.wssecdsig.Sign;
import com.google.apigee.xml.Namespaces;
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
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class TestWssecSignCallout extends CalloutTestBase {

  static class KeyCertPair {
    public String privateKey;
    public String password;
    public String certificate;

    public KeyCertPair(String privateKey, String password, String certificate) {
      this.privateKey = privateKey;
      this.certificate = certificate;
      this.password = password;
    }
  }

  KeyCertPair[] pairs =
      new KeyCertPair[] {
        // generated in this way:
        // openssl genpkey  -algorithm rsa  -aes-128-cbc  -pkeyopt rsa_keygen_bits:2048 -out
        // private-encrypted-genpkey-aes-128-cbc.pem

        new KeyCertPair(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                + "MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIekZWpLB7vfoCAggA\n"
                + "MB0GCWCGSAFlAwQBAgQQj5BPR5/Fy0guLNGP0ALaugSCBNBLe7qE0cimL7hn7AAv\n"
                + "Ll12m9frCQ0iOofYaP6coNYN6AzW1HXOyWXR4GDbUVRWAistT+2qEc1siiXje/Fh\n"
                + "lcXarvflF1FZlfSFk/Jqsz8EPhr/qBjXp20LzR9Sp6Ze3/zO3tCnadrvu0DJScYm\n"
                + "dCgGV7L12OAd0mrWuQ0qpJzu2xQr+LBSoevGrycTK4TYDy2nNjJItuVZbscf6wND\n"
                + "r00KErrDlDTUBkE5akgmPNmXFqDzPw2SPz08FzsT5Srnom1y1mBCSYT2YhSsucUW\n"
                + "hMQFEdgpE8H6exu/DElkjj2ziMH2Pbn5uLpQpDHx50rCSiMCJKm79OWAerLUiPXG\n"
                + "d3R/3mzSHVjTVIfqe3dns5QHx7DZ5QgjWKs4IBrdu9+3azdgpq6n8sfCpTFd1T5i\n"
                + "EXjLjSauiZ+rEmrKZ8Fbv6Xl3yWKT27+pP58AmZGTtOOph4f+Oiuggja/cJfm+Up\n"
                + "tDM9c3E7EJVTPsZBjDtZJrvnvAWsED6DbRQ2J1wPyLIjFST70YZbdoMOvx603tnh\n"
                + "NuOOouFvgQorbejec5X7a5mfCJY4oV8QRV/k2pKjXkKrB+APvfyYikTlVivJNew1\n"
                + "WOL6bL+o3AOCIzKUtBRbJWTaSJpP7JoS9mnef2vh3qE6q9zuhogD8igphUxBwUbW\n"
                + "AcOsFvS1yyJ4SdHebJplh7rR+IVOn5ytRLQ7+6copqU+m6tmyhP59swAwyhemgpm\n"
                + "QiOpTHi/F7eWTXZ/Ct/qKpSu7ZOmTGaLoixzkEdH4uUoVmYLnSB+UmN2S2K0T50e\n"
                + "mD6W8950VkhCup2/KX7vXIXTHDwIWWbT/oOwvkzaoaJGD+R823+UNreX23HbYKy/\n"
                + "xsZVB5nb04udX7yoYdhd9cMaE+oDMfCTHYQe8FqNt6akLLaCfj5TCQQTiWhq4raw\n"
                + "U8poQiFUWCSNCSLHidRDvzI07SxZJMsGtA4cBRFRNHbfSwRbg6cBdmXn3R3zYHyG\n"
                + "Vptr66VaGdoYRiLrhxrnDOgGHHmSjqCTjcJj3JwT2nAtXgRg2ZZ/uWZCk1DkSh1u\n"
                + "eH9kG5PLc+xG1NmWtR8oKCzkCY/p+ZekAuvzT+Hhn00Ww7h5chcy6ZDDIbfGK/Is\n"
                + "blOPy0CYlpB7fKS3LWoVRI+nfYmS7lDsdKH/EhhtNN1QaIuHdlTtN2Bk6rUV9QD2\n"
                + "La4Pq5WvFV5pKp59Dse5rDHyKQIwMyHcj/kMyEaC8Upp6JEmNr9iKuprpB5Ty5u/\n"
                + "3MMxDr6Rl0SJjbddJYYWEhtlB6pLAImJJkKCL5p4kg6WZBytYRiIK8qs9NtlR/d1\n"
                + "iDyBqTinEPy7EOCxe9vLM0zAStVsM2QD+VDgG1G5G/EQf/v41Ojdp+INsiF7tKM2\n"
                + "4Ta6ib5PUkXZsn18DcqhD4+/TY47N4FcqIEswFanQ0keCmr0vRzzznIgJEuhHM/x\n"
                + "hZB8fZw2zWQu9CiHjKuMqwZA6K4peMaQigZDEuMipAx5k8lERnm9qrGNHDCQCWmc\n"
                + "c596ZSySS4xCkpVNWr9xsfx2bGYayNFtaflmEZFSk/yKrqPkzUWCKW3nythlstNC\n"
                + "Wi58YrP475R6va0mfe3XdNjxv9FPG/GgMMJ2Djo+DZl717I8+OAVrzWlntb0JHK1\n"
                + "Jl2+bIFwj5N2I9OmJv/xNUE5XA==\n"
                + "-----END ENCRYPTED PRIVATE KEY-----\n",
            "Secret123",
            "-----BEGIN CERTIFICATE-----\n"
                + "MIIDrjCCApYCCQCCUoSwpL/QFzANBgkqhkiG9w0BAQUFADCBmDELMAkGA1UEBhMC\n"
                + "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xDzANBgNVBAcMBkF1YnVybjEPMA0GA1UE\n"
                + "CgwGR29vZ2xlMQ8wDQYDVQQLDAZBcGlnZWUxITAfBgNVBAMMGGF1YnVybi5hcGln\n"
                + "ZWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMB4X\n"
                + "DTE5MTAwODE2MzY1MVoXDTI5MTAwNTE2MzY1MVowgZgxCzAJBgNVBAYTAlVTMRMw\n"
                + "EQYDVQQIDApXYXNoaW5ndG9uMQ8wDQYDVQQHDAZBdWJ1cm4xDzANBgNVBAoMBkdv\n"
                + "b2dsZTEPMA0GA1UECwwGQXBpZ2VlMSEwHwYDVQQDDBhhdWJ1cm4uYXBpZ2VlLmdv\n"
                + "b2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTCCASIwDQYJ\n"
                + "KoZIhvcNAQEBBQADggEPADCCAQoCggEBALN70y1o8/ArttO7E1RvaZg6RZZJ9PM4\n"
                + "iM2g0F4B6DAoSFP86Yd+v/OXYpXDA/3vEfqUQ6FSqBS4997OXAJfAoSptJwIAXkX\n"
                + "WK3ywmbxVfSaYEo3oNCDIHosGKUwd9xcuRGrIgtas2T5algElCg7GTc1d5Kz2FXG\n"
                + "TZDfcgzigBh68nSIWeuqQuNwwXtGDJtXoLBXugn2ln+IBDprFczPPk0xdmwlNc/Z\n"
                + "6KuwOEdjdcBGFTtg14bw/4gReSCsXa/J8JKS/BZJb0Y8skugHfYkIOk9ka677PYT\n"
                + "x6XiOrpSdn9efHyBad5J7Bkdl2FnNCXDaB55UPyRqwxZx5V90aRHw68CAwEAATAN\n"
                + "BgkqhkiG9w0BAQUFAAOCAQEAmqCfZGJAyhr4ZUvMOeilxXB7rupHtKODnOhQAULq\n"
                + "wXDFVgSVcnRET65mX1BGu9bbVuBB9nNLRa1Y2dkonm/dkSjHNKOOeDIPV/pLaRq6\n"
                + "dF5Ykojt6/A7JjZcX9xmBryZToxWCS/Jc2LURI7lhdq6EYkNx4CkqaiBLAXUOTAK\n"
                + "ioTcVIp3R//odmiED7/69g4TorHmWhsLLDbOUV5BLsUExLvjIDE+nLNA9cpVxRGp\n"
                + "IPvGEtT4k7i/Z3Tb3Iie/7buuTiw9zk99q0SDzX+YIcFRAPgIPn70G9eECMDH1QR\n"
                + "RpA9oUg0EWTbKG8dw+PgMIrg6jm9Vj8VbWsr4SPsOZi5LA==\n"
                + "-----END CERTIFICATE-----\n"),

        //
        new KeyCertPair(
            "-----BEGIN RSA PRIVATE KEY-----\n"
                + "Proc-Type: 4,ENCRYPTED\n"
                + "DEK-Info: DES-EDE3-CBC,0C1C2CD76485906E\n"
                + "\n"
                + "0mMQfL7TljeaVR2oVSNZNSFR74+7Cw8fniiWjkIV4DkTN0kgz+cCBHz6axIwraOU\n"
                + "P+1B9W/LUbM9SjvxgqZvX2tSVEc/18dKE/QCgo+MDYxs5aqjFdJErEC8oANMy7SL\n"
                + "fqr3TyyYIA+/LSJirAylIeJAwLG6chrxBAUYCAXT2yXg8bbdGQSJH8mRT9hHgO78\n"
                + "wQ0laFn0Ds3FYHSuCA9Q2InogybIPzYihK0i2vhjD/b2npvYYEA6mVWMEG+4K/JP\n"
                + "YHPoOWJZLDcKHrKno0s5m5AP+Smh2wQJHGebNyhNukOLx5okcRaxRbg6s+l/Bu2i\n"
                + "Xzbi3QSePX8Ke6GW2iMkHcunguVnyR8BcZc54RAiTvEnuabsvHU5U6LjTR1OLev8\n"
                + "cVJuIeUNifraehjtepgGPmkvB5M0DnLnQtpHUQhyO/eNuTYW2shmdSH1p5paohKZ\n"
                + "lSFkCIxroTqcJWnu8QSA3O6BHTDAkVh2rNbjegaJINsbt0PFR7SQMOdE0hgbfb41\n"
                + "gStWSkjinAu7DBDqTUoFoXFUDMxNKWVKOtHAGLBiWbMayEXTuH8+zVn3n4nuMBZg\n"
                + "NfurwOsWPiJQ5ZTQkIb/JO+7FtwCPsucq9FBZwGuq+RT0Dl1WjNHZ9YNzwQWCYCx\n"
                + "pkTrchD5Gdh8wGMwaUW+Vg7irmGmIjNSfcnVpFXfSUtFmrd069I7n8Y4avz5uXK+\n"
                + "JY0z4DSO9DLM62K1Gp4kTdjxMdxK/QOtKO4eLSocY01N65f/pkWGbGJy3kIVahh5\n"
                + "hOiS3m4fAeVXYoety3p2QIsky1ykX3wAOwnoZHfvfP6bboRhttr5BnYd3OZ0n/OJ\n"
                + "+2Yd3nc0G67sCGQOzCQRoqn6+cuTKqB6ICBGNe2hVNoElzfUHOXI6IeKG40Z79vY\n"
                + "I0SuPrzAbSfdsQqJPplR8un8cKwGwx8GKCV2T+sQSj+rT8BNKt69dhwdT10FqCVi\n"
                + "5Cle5PSjUTc43IFZX6aqpytNzzavdXerZAOTKwRmeEM0HuhWWvE8YETIGfnaFXHE\n"
                + "uYQyg3AMgKDTV4z9gH6lBpWFmFBTfgwbEMSWy8bsQxai3MYbLl08EWL3wbUhUKER\n"
                + "WSCYigSyfSasDSlbyqcwV7FLupbWiSQH3sJExg3RKQgiHJ6QMsG0jXLMjtSfAY9L\n"
                + "r3rX6Fvub4eN91Ld4tbqItz1FiFZQtyy5o3wNC+1PRzInvQ9/d5fsIQ9NzSmogG7\n"
                + "TPSmvMSevbAZWxVmqv+XCIXaXA5QctUHbluXoN8EbF3N7pipwMlHrkUQuwMUduZj\n"
                + "nPnnBsQU0Hv/+TWwsMcMrv6nZEzGmy9+yNWBRqSVI2zDgyVRVbsGKGKOOI9Gmuqf\n"
                + "JcQUbpo1OmRz9v7deriHYInWB2Gxx82N14QROHDhGccx17BbzGJIXpUzePDXk7Bc\n"
                + "BJhoKW+AIjvSgv5BOBVZGEJ0HDBL5zAVkZU8/YlRzeO2tKtDulP56D6tMGsc+lGi\n"
                + "/Yb1+cruEMtyQInHJ29dBt8GM9M8y9VhspSq6sTedWKoBNpanmrH3QGfcgFLQ1Yy\n"
                + "h59VJWhfbf4UrghV4zCYAP8r4/dQSb/GqBC56IIMbQYl6R3Q08tOle1ufFIqiJAv\n"
                + "-----END RSA PRIVATE KEY-----\n",
            "Secret123",
            "-----BEGIN CERTIFICATE-----\n"
                + "MIIDpjCCAo4CCQCCCFpZuM87ujANBgkqhkiG9w0BAQUFADCBlDELMAkGA1UEBhMC\n"
                + "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xDTALBgNVBAcMBEtlbnQxDzANBgNVBAoM\n"
                + "Bkdvb2dsZTEPMA0GA1UECwwGQXBpZ2VlMR8wHQYDVQQDDBZrZW50LmFwaWdlZS5n\n"
                + "b29nbGUuY29tMR4wHAYJKoZIhvcNAQkBFg9kaW5vQGFwaWdlZS5jb20wHhcNMTkx\n"
                + "MDA4MTYzMzI2WhcNMjkxMDA1MTYzMzI2WjCBlDELMAkGA1UEBhMCVVMxEzARBgNV\n"
                + "BAgMCldhc2hpbmd0b24xDTALBgNVBAcMBEtlbnQxDzANBgNVBAoMBkdvb2dsZTEP\n"
                + "MA0GA1UECwwGQXBpZ2VlMR8wHQYDVQQDDBZrZW50LmFwaWdlZS5nb29nbGUuY29t\n"
                + "MR4wHAYJKoZIhvcNAQkBFg9kaW5vQGFwaWdlZS5jb20wggEiMA0GCSqGSIb3DQEB\n"
                + "AQUAA4IBDwAwggEKAoIBAQDCAN92+xe9jMUASg3qOregR7h38BaHotmckmWQ0JRQ\n"
                + "wZLfch8aywOY/UMQkHPBKMugAgulVR0jsx2+Tn38hWdQIaneFFKXye4xHndbDSWo\n"
                + "sBjEyNrNJYY4x+mCwbHvgIAQhrP8w9iaQVaATWhA+ltpql4VUO2PjLkKzO/oUfY6\n"
                + "4wNuEvYDtaWokvvM0iOrjoSSEVhDMw6iY+mQNIXX5nYWzNUOHF+4K9zTMQWYy2mc\n"
                + "1AnnoE+1r2QFSL88rEKzpR9/IWSO3hXYhk2AUA+FraABUiXx1hAFTzXO4gELDzyQ\n"
                + "fRnsaaZCSRmueF4lRIuSB2vc7kkrRNbSct9it+C3a/TRAgMBAAEwDQYJKoZIhvcN\n"
                + "AQEFBQADggEBADkNjGpJ3l8PvUJgxkZJN6XzXP4l1iOQPOSoJx0K5IGPrroW7syl\n"
                + "rf7Py5ZjhiWrbl4YK+8/dm65m0Cuou6WC9kNgbdCDnijvtsVYH0sLJdputg30PHC\n"
                + "6bnaCf3Rb9b1aPTcqATHPGSjvHtbH5WPM9HXJusQHJ3JlWBQX2ARYIP3zp/4Jziq\n"
                + "0ilwFLXwwOFEvPpriAGVPNBL7NEpWOKnuT20UuR1y+YH8I/RQpL7z3x7wa0Qaeef\n"
                + "TUBlHaSiomLDFP0RP3pM8JNQfU24zoZn2XFlBNRdk0ct50KaH5p6Y/eEls1spP1J\n"
                + "hAHIUq6UU664nfE/LZjtL2rgHLqlD1g/aAI=\n"
                + "-----END CERTIFICATE-----\n"),

        // generate an RSA key in new format without encryption
        // openssl genpkey  -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out keypair.pem
        new KeyCertPair(
            "-----BEGIN PRIVATE KEY-----\n"
                + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCokDY3Bd6pdpVo\n"
                + "c7SaQoOlN2E8KH/zSAfY66fgMk5iNiC90xEnzfEHofCbzT1Pn3euRf0/A6NQNDuQ\n"
                + "m8fRotqrFv4WutMNMVxdlclnrl1xr2VgBHGAQDBqw8iS8F2vSc/ZbZVCA8q2TBK1\n"
                + "mKcyImH8lKVcLPtQsMZWpbwXKSUZpUiTGteEeyMf6GEnwqn7OMWx92xOQZtqpeP+\n"
                + "p7F4dQFwXoZsd7vGFouiP8/bgPuYUcHe5fHi83eiE/5mJPXLlfx8ItW7lJIL68MU\n"
                + "dHZnkjbrJOVw1HAq3biU3KkawTMzkpkgsmUSvcGcADWqRxJfvBlAMendc4ckdpHq\n"
                + "XFqu9iWZAgMBAAECggEBAICZXTNHQCOLe9svgxa5LhRLFty9jTg+uPXue6oY1yIo\n"
                + "Z3xK3ei/PmbzTkyfHWp0n+sOLHH5xYu3/cWKg7zVAPzMUtdmewOyp+QiFYELTvEf\n"
                + "vjityyXsUsPxUEGCLgdASdl4uAmgOPQxP4jZyJ0ADD+V7D5Rdv6NjxOl58THuC1C\n"
                + "ZUq5wyJpm9U+MeUWCYJHWTh3Nj5BVdokYA4G0SeAMuQsGAWXQTR1VTrFEPEouX8a\n"
                + "mCTMYHQP5mfrPD+gAYKGPrjwVyZZI8CnqfxlNhkSt3etuXbHjHHzPb6mPNjOJKgU\n"
                + "5xS5I737wKR1kF0NM14WTeCvSzFNAgo9E9yfVTxIXjECgYEA3rgIgUoA3lk8lsJ/\n"
                + "uOjYRMyDgiYVJ3GMyZ7ll+LqkWRWhEx69NiNeMED32oqKMxBvvM+Q/wgoC5rHJTM\n"
                + "Nd1jbzlqGscJqlW66x8r5bXY9iwhJhiNpNlj+FIPaXktivVG741qTLWnsM5Rrv8L\n"
                + "7leZjEsWNJWAw90FhJTaZ7A3dp0CgYEAwcB+LqjNQQdmNSyBaLTb6Shr6IgOCf/1\n"
                + "NHlqatFsdmy8F2+5+ePExpb7HCbiY5Gi96JBczZ5qEK/yzAIC8WWCLxvtPn/x/vE\n"
                + "ByO7ZXa4dN80KENta0sWWdV3mNFoqU1TR8Cno5a8a3A705CFjI6kSLDxhOSeBfuF\n"
                + "JzErU/oXvC0CgYAF6AeBtj6zptYugVX1x2cE3A+Ywf3Jn/9F0YrxLjleRbTtqUGR\n"
                + "gLSvwR6jLCOWFWSg9b5u+x66YMDCb0fDHe3nIzSnJSQiekeMuLTnUJ1CWgU/B2Oq\n"
                + "PYGjMjnqaCZHCx4oeC2bfy3FSJNt+qGMXpJZ4BvkpRpXF2NwEqqAGXI/GQKBgDam\n"
                + "y3Dx4GO1aJkbIq2cRmOwKTAAIKWlc08H6IKU7BlDdpLNyxG3s6uortA0D6uyStu7\n"
                + "AucyuIJDwcHYnIxlgXqZXJEZ65JHa/XvmE54fHNK+nVY/6ZCGd3hHskWWIVY8GLO\n"
                + "7vpv7FoJ4HY+z8zj92chsh6gNgrN9bMmZWhcpRFJAoGAMih1rmZx8PBwrnkMvwVB\n"
                + "05Ar+LdS/CqG9egQJxtRSIzfdyc9CrZ6b7Sj+VWjieT/o78ODalbXQETia6bYv5b\n"
                + "KWHu/XSeFDzGfCsZiGWECY0rpEKjvI8OBYljTKmB/14Iz51m8jgZRvTaoauUUpZi\n"
                + "w+4PGMrpoKCGFBE4ucT7AvY=\n"
                + "-----END PRIVATE KEY-----\n",
            null, // no password for private key
            "-----BEGIN CERTIFICATE-----\n"
                + "MIIDpDCCAowCCQDsXkZg2rbAwTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMC\n"
                + "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtpcmtsYW5kMQ8wDQYD\n"
                + "VQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTEaMBgGA1UEAwwRYXBpZ2VlLmdv\n"
                + "b2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2VlLmNvbTAeFw0xOTEw\n"
                + "MDgxMTExMjBaFw0yOTEwMDUxMTExMjBaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UE\n"
                + "CAwKV2FzaGluZ3RvbjERMA8GA1UEBwwIS2lya2xhbmQxDzANBgNVBAoMBkdvb2ds\n"
                + "ZTEPMA0GA1UECwwGQXBpZ2VlMRowGAYDVQQDDBFhcGlnZWUuZ29vZ2xlLmNvbTEe\n"
                + "MBwGCSqGSIb3DQEJARYPZGlub0BhcGlnZWUuY29tMIIBIjANBgkqhkiG9w0BAQEF\n"
                + "AAOCAQ8AMIIBCgKCAQEAqJA2NwXeqXaVaHO0mkKDpTdhPCh/80gH2Oun4DJOYjYg\n"
                + "vdMRJ83xB6Hwm809T593rkX9PwOjUDQ7kJvH0aLaqxb+FrrTDTFcXZXJZ65dca9l\n"
                + "YARxgEAwasPIkvBdr0nP2W2VQgPKtkwStZinMiJh/JSlXCz7ULDGVqW8FyklGaVI\n"
                + "kxrXhHsjH+hhJ8Kp+zjFsfdsTkGbaqXj/qexeHUBcF6GbHe7xhaLoj/P24D7mFHB\n"
                + "3uXx4vN3ohP+ZiT1y5X8fCLVu5SSC+vDFHR2Z5I26yTlcNRwKt24lNypGsEzM5KZ\n"
                + "ILJlEr3BnAA1qkcSX7wZQDHp3XOHJHaR6lxarvYlmQIDAQABMA0GCSqGSIb3DQEB\n"
                + "BQUAA4IBAQBD+S4bF8b07955E7HshWFez5Q4/7cXhGPjFaiNw9lH9Ny1iIcblRl3\n"
                + "6iiVda4Lemy1Kxa5xGJ+I5NZ8k1MyxZ1x5K9bPX5LiI8ThLGRxBNUNLgaoQ+7FZL\n"
                + "klpZARoIuQ3Gg90V0qUqkm2eipgZxzdtEGj+lqoX10A2B+wimO6nzUv6vYoJARMB\n"
                + "tqsYmQKz5GRBoajGdMn60UF9Ry5B32k31JVpat4qm7+Ig1YMwv2nfY6bgHzsI4Wj\n"
                + "ETOLvFCYgBDJzIEy+0jA1FUe5Ec5Fs5nmiG8F7FRJ/9aYb1e+cbQVRZyc1wKlmIR\n"
                + "eK/LgG8FjdDjeqFZTg0AjInG8/oOz5ib\n"
                + "-----END CERTIFICATE-----\n"),

        // generate an unencrypted RSA key in the old format:
        // openssl genrsa -out keypair-rsa-2048-unencrypted.pem 2048
        new KeyCertPair(
            "-----BEGIN RSA PRIVATE KEY-----\n"
                + "MIIEpQIBAAKCAQEA3/Kz9Ft3OGzVKc6XztaZPcjVD8eVCqvFc4ezZ3e9DC5s59c3\n"
                + "In0XNiarxYu5Djn5DMzcLM4Zw7oLiwYLfHCQQMLt0ujty8jKuDkrt65zvxSxQ4Cb\n"
                + "L66v8DN/LQ3OX6TXK3S7WrRckpkbyqSw08HX2qVacVTssN0S62ZGh6pqhW/H6knk\n"
                + "b6lvrnGd/GbTopPZseQNwXLqhGd/xNwWKwDNBfmdabS13RYQJY5qEZxCWZU0RVbF\n"
                + "8p1SRPJh9InAXPY+Smrmo6ets6YJehmn08XNR2dZS/ZeHJcMI+ejGJuwMmRcqI8P\n"
                + "7DYFoMXY2IIf60TVvALggJNCc/idPi2aTSO1oQIDAQABAoIBAQCyMjknEzDGYTMs\n"
                + "1QrOtsuw8gE3USQzHYM77pq+lfSDoN1fjUx90POLTzIXOprByzd1C/2WWVj++Sb+\n"
                + "NI0nM5pVLcZ3sIinQtqrxDIZMmM/hIOYptjVFDdC9ncXroisakocdgIupp2SuOn4\n"
                + "URuzI+dSP4i77Ut5YDARx4wPn3arPU1R4ZlpFAFqu9+tUVPgt76qTsHml6y+XrpS\n"
                + "14EVhJQefzFYt58s0mO5T01Pe1PnTnjqMARpaLyXZMvbMTJLfkG7QFc98kcon0VW\n"
                + "xQpIXTByRBvyZf24Be3+ry7OLAD+DatnzygN/At8W74BQD/3qwjNWQgNMvvxTSuh\n"
                + "3Dqsiw3BAoGBAPwyrrzW8JM2hg/BLk57JSMB9lJIiGPP9XeinVrjRvC28jfwvEMi\n"
                + "Nk3hEDG3/vrwUz7KnhfJ4SHXr89YZUi/2yb8pOOsV6S1nmTInx0R+cRkBAghngHT\n"
                + "urYTM4zO2I87IV2Hnj2RN9+GXu/pgt01j/mbXHRSr1BH50n8j4qxnDXdAoGBAONS\n"
                + "/o7F1vObOFd/sCOrNt7kfQSrlwkPnrODQnZ9IQCuDYsYqzLy3pP3YrddSIL0mwxa\n"
                + "QgExzS86dC2Pm/eZucRVIIDsJtUeR9M9v+SHIEBYGqbElGh4DHmLlRfuUj470arr\n"
                + "oogu3obooKEeSkkNgX0a4zrNZts8QyNjMkYnWgyVAoGBAKpsmXZVDWd93eRBmEhC\n"
                + "oVrh1ZHPIBPLEUbSJeGoWmUKS+6PiLkZIndIUsg2XWE4DBkPlPvgWXmkJlNImdEq\n"
                + "jS7wZYDRErzkWnAivptHbXBQYgUYqozzhmXJ3fkWQnOv8qEgp0dVnds4E2muc9eG\n"
                + "fY+gdD7LLVtj66EswddopHYlAoGBANXq+/GO60BDCToNxstKC1Ck46DJeE/miwmS\n"
                + "s7Cc/7mMEOKcTD6dnibP3e1/swTI+j8dkI9fNh8DeuCFC9hsqQvAr92iXMigviZj\n"
                + "LXj4T7k9L5dP1fiZP+QBHkRu2KYH1L5rD3/n2zBJKR91SaKFOx1nd/2V3PziMKvU\n"
                + "ZTLvRSYhAoGAWEkEX3RnYrAKeyG1CtAVUM/uhyC00V5WQsI2heMyuf1t6BWJzkLq\n"
                + "wkOmt1V6JleAoCY24Nt+NK65CXfCt6iZH9vF3CsiMr1f8D8Tprx2r4lhrUGrEh7U\n"
                + "AliWsYfrgJ9ZcIu+prksc9zAmT+aSqPYRzMDBQ5d+sSthDSXdfTKE2g=\n"
                + "-----END RSA PRIVATE KEY-----\n",
            null, // no password
            "-----BEGIN CERTIFICATE-----\n"
                + "MIIDvDCCAqQCCQDs3rlzLqs8KjANBgkqhkiG9w0BAQUFADCBnzELMAkGA1UEBhMC\n"
                + "VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCVN1bm55dmFsZTEPMA0G\n"
                + "A1UECgwGR29vZ2xlMQ8wDQYDVQQLDAZBcGlnZWUxJTAjBgNVBAMMHGFwaWdlZS5z\n"
                + "dW5ueXZhbHVlLmdvb2dsZS5jb20xHjAcBgkqhkiG9w0BCQEWD2Rpbm9AYXBpZ2Vl\n"
                + "LmNvbTAeFw0xOTEwMTUyMTI1MzJaFw0yOTEwMTIyMTI1MzJaMIGfMQswCQYDVQQG\n"
                + "EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJU3Vubnl2YWxlMQ8w\n"
                + "DQYDVQQKDAZHb29nbGUxDzANBgNVBAsMBkFwaWdlZTElMCMGA1UEAwwcYXBpZ2Vl\n"
                + "LnN1bm55dmFsdWUuZ29vZ2xlLmNvbTEeMBwGCSqGSIb3DQEJARYPZGlub0BhcGln\n"
                + "ZWUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3/Kz9Ft3OGzV\n"
                + "Kc6XztaZPcjVD8eVCqvFc4ezZ3e9DC5s59c3In0XNiarxYu5Djn5DMzcLM4Zw7oL\n"
                + "iwYLfHCQQMLt0ujty8jKuDkrt65zvxSxQ4CbL66v8DN/LQ3OX6TXK3S7WrRckpkb\n"
                + "yqSw08HX2qVacVTssN0S62ZGh6pqhW/H6knkb6lvrnGd/GbTopPZseQNwXLqhGd/\n"
                + "xNwWKwDNBfmdabS13RYQJY5qEZxCWZU0RVbF8p1SRPJh9InAXPY+Smrmo6ets6YJ\n"
                + "ehmn08XNR2dZS/ZeHJcMI+ejGJuwMmRcqI8P7DYFoMXY2IIf60TVvALggJNCc/id\n"
                + "Pi2aTSO1oQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQCbXDGIPZ/C+5nLSnZN/vlQ\n"
                + "ndaUrrzhhZMorywyL5aZp+Em7bWg475xJy4QLDKWM5JQi66DxGdkJ7oDV/RT7cFc\n"
                + "2lCk84bDw9agA7Q3N38qdrIck1/EfgWAQgMeGYP8hg3do+5Bc+b8f2C9WV2lVF3z\n"
                + "QVuEom5JsLlbhIWSVsQniRE3wSj5PUXDCLMBxvoOhq5+uNvDPD21rETX13s3AT0E\n"
                + "WB+XsRDi4B69LZvji6logh3g5Osu86TOV/nqapovLUgvNky259sLouxNZRx/1SRT\n"
                + "EHNOScTDSZhEsysd9MnO/hphNmSjoVxz5dUvxwYz7MaHcPeUAPkI3KKJRJU5e2gh\n"
                + "-----END CERTIFICATE-----\n")
      };

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
  }

  @Test
  public void missingCertificate() throws Exception {
    String method = "missingCertificate() ";
    String expectedError = "certificate resolves to an empty string";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[0].privateKey);

    Map<String, String> props = new HashMap<String, String>();
    // props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertNotNull(exception, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertNotNull(errorOutput, "errorOutput");
    Assert.assertEquals(errorOutput, expectedError, "error not as expected");
    Object stacktrace = msgCtxt.getVariable("wssec_stacktrace");
    Assert.assertNull(stacktrace, method + "stacktrace");
  }

  @Test
  public void validResult() throws Exception {
    String method = "validResult() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
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
  }

  @Test
  public void signSha256() throws Exception {
    String method = "validResult1() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("signing-method", "rsa-sha256");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
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
  }

  @Test
  public void digestSha256() throws Exception {
    String method = "validResult1() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("digest-method", "sha256");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
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
  }

  @Test
  public void signOnlyTimestamp() throws Exception {
    String method = "signOnlyTimestamp() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("elements-to-sign", "timestamp");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
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
  }

  @Test
  public void signOnlyBody() throws Exception {
    String method = "signOnlyBody() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("elements-to-sign", "body");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
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
  }

  @Test
  public void withExpiry() throws Exception {
    String method = "withExpiry() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", minutesExpiry + "m");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
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
  }


  @Test
  public void thumbprint() throws Exception {
    String method = "thumbprint() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", minutesExpiry + "m");
    props.put("key-identifier-type", "thumbprint");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
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
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
    Assert.assertEquals(nl.getLength(), 1, method + "KeyInfo element");

    nl = ((Element)nl.item(0)).getElementsByTagNameNS(Namespaces.WSSEC, "SecurityTokenReference");
    Assert.assertEquals(nl.getLength(), 1, method + "SecurityTokenReference element");

    nl = ((Element)nl.item(0)).getElementsByTagNameNS(Namespaces.WSSEC, "KeyIdentifier");
    Assert.assertEquals(nl.getLength(), 1, method + "KeyIdentifier element");
    String thumbprint = nl.item(0).getTextContent();
    Assert.assertEquals(thumbprint, "ada3a946669ad4e6e2c9f81360c3249e49a57a7d");
  }


  @Test
  public void issuerSerial() throws Exception {
    String method = "issuerSerial() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", minutesExpiry + "m");
    props.put("key-identifier-type", "issuer_serial");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
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
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
    Assert.assertEquals(nl.getLength(), 1, method + "KeyInfo element");
    nl = ((Element)nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
    Assert.assertEquals(nl.getLength(), 1, method + "X509Data element");
    nl = ((Element)nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerSerial");
    Assert.assertEquals(nl.getLength(), 1, method + "X509IssuerSerial element");
    Element issuerSerial = (Element)(nl.item(0));

    nl = issuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerName");
    Assert.assertEquals(nl.getLength(), 1, method + "X509IssuerName element");
    String nameString = nl.item(0).getTextContent();
    Assert.assertEquals(nameString, "CN=apigee.google.com");

    nl = issuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509SerialNumber");
    Assert.assertEquals(nl.getLength(), 1, method + "X509SerialNumber element");
    String serialString = nl.item(0).getTextContent();
    Assert.assertEquals(serialString, "17032128222562009281");
  }


  @Test
  public void issuerSerialWithLongName() throws Exception {
    String method = "issuerSerialWithLongName() ";
    int minutesExpiry = 15;
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[2].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("expiry", minutesExpiry + "m");
    props.put("key-identifier-type", "issuer_serial");
    props.put("issuer-name-style", "subject_dn");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
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
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo");
    Assert.assertEquals(nl.getLength(), 1, method + "KeyInfo element");
    nl = ((Element)nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "X509Data");
    Assert.assertEquals(nl.getLength(), 1, method + "X509Data element");
    nl = ((Element)nl.item(0)).getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerSerial");
    Assert.assertEquals(nl.getLength(), 1, method + "X509IssuerSerial element");
    Element issuerSerial = (Element)(nl.item(0));

    nl = issuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509IssuerName");
    Assert.assertEquals(nl.getLength(), 1, method + "X509IssuerName element");
    String nameString = nl.item(0).getTextContent();
    Assert.assertEquals(nameString, "C=US,ST=Washington,L=Kirkland,O=Google,OU=Apigee,CN=apigee.google.com,E=dino@apigee.com");

    nl = issuerSerial.getElementsByTagNameNS(XMLSignature.XMLNS, "X509SerialNumber");
    Assert.assertEquals(nl.getLength(), 1, method + "X509SerialNumber element");
    String serialString = nl.item(0).getTextContent();
    Assert.assertEquals(serialString, "17032128222562009281");
  }


  @Test
  public void oldFormatPrivateKeyEncrypted() throws Exception {
    String method = "oldFormatPrivateKeyEncrypted() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[1].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[1].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("private-key-password", pairs[1].password);
    props.put("certificate", "{my-certificate}");
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
  }

  @Test
  public void oldFormatPrivateKey() throws Exception {
    String method = "oldFormatPrivateKey() ";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[3].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[3].certificate);

    Map<String, String> props = new HashMap<String, String>();
    props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
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
  }

  @Test
  public void oldFormatPrivateKeyEncryptedNoPassword() throws Exception {
    String method = "oldFormatPrivateKeyEncrypted() ";
    String expectedException =
        "org.bouncycastle.openssl.PEMException: exception processing key pair: password empty";
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[1].privateKey);
    msgCtxt.setVariable("my-certificate", pairs[1].certificate);

    Map<String, String> props = new HashMap<String, String>();
    // props.put("debug", "true");
    props.put("source", "message.content");
    props.put("private-key", "{my-private-key}");
    props.put("certificate", "{my-certificate}");
    // props.put("private-key-password", "Secret123");
    props.put("output-variable", "output");

    Sign callout = new Sign(props);

    // execute and retrieve output
    ExecutionResult actualResult = callout.execute(msgCtxt, exeCtxt);
    Assert.assertEquals(actualResult, ExecutionResult.ABORT, "result not as expected");
    Object exception = msgCtxt.getVariable("wssec_exception");
    Assert.assertEquals(exception, expectedException, method + "exception");
    Object errorOutput = msgCtxt.getVariable("wssec_error");
    Assert.assertEquals(
        errorOutput, "exception processing key pair: password empty", "errorOutput");
  }

  @Test
  public void mismatchedKeyAndCertificate() throws Exception {
    String method = "withCertificateMismatch() ";
    String expectedError =
        "public key mismatch. The public key contained in the certificate does not match the private key.";
    String expectedException = "java.security.KeyException: " + expectedError;
    msgCtxt.setVariable("message.content", simpleSoap1);
    msgCtxt.setVariable("my-private-key", pairs[2].privateKey); // mismatch
    msgCtxt.setVariable("my-certificate", pairs[1].certificate);

    Map<String, String> props = new HashMap<String, String>();
    // props.put("debug", "true");
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
  }
}
