package com.mendix.cloud.urlsign;

import com.mendix.cloud.urlsign.exception.functional.URLVerificationInvalidException;
import org.apache.commons.io.FileUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.net.URI;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BaseTest {

    private static String privateKeyFileName;
    private static String publicKeyFileName;

    @Before
    public void setUp() {
        privateKeyFileName = getClass().getResource("/id_rsa").getFile();
        publicKeyFileName = getClass().getResource("/id_rsa.pub").getFile();
    }

    @Test
    public void endToEndTestSuccess() throws Exception {
        URLSigner urlSigner = new URLSigner(new File(privateKeyFileName));
        URLVerifier urlVerifier = new URLVerifier(new File(publicKeyFileName));

        URI signedUri = urlSigner.sign(new URI("https://www.mendix.com"), 10);
        assertTrue(urlVerifier.verify(signedUri));
    }

    @Test(expected = URLVerificationInvalidException.class)
    public void endToEndTestFailure() throws Exception {
        URLSigner urlSigner = new URLSigner(new File(privateKeyFileName));
        URLVerifier urlVerifier = new URLVerifier(new File(publicKeyFileName));

        URI signedUri = urlSigner.sign(new URI("https://www.mendix.com"), -10);
        urlVerifier.verify(signedUri);
    }

    @Test
    public void simpleMessageSignVerifyFileConstructor() throws Exception {
        URLSigner urlSigner = new URLSigner(new File(privateKeyFileName));
        URLVerifier urlVerifier = new URLVerifier(new File(publicKeyFileName));

        byte[] message = "lorem impsum sit dolor jeff ament".getBytes();
        byte[] signature = urlSigner.getSignature(message);
        assertTrue(urlVerifier.getVerification(message, signature));

        byte[] wrongMessage = message.clone();
        wrongMessage[1] = 'f';
        assertFalse(urlVerifier.getVerification(wrongMessage, signature));
    }

    @Test
    public void simpleMessageSignVerifyStringConstructor() throws Exception {
        File privateKeyFile = new File(privateKeyFileName);
        String privateKeyContents = FileUtils.readFileToString(privateKeyFile);
        URLSigner urlSigner = new URLSigner(privateKeyContents);

        File publicKeyFile = new File(publicKeyFileName);
        String publicKeyContents = FileUtils.readFileToString(publicKeyFile);
        URLVerifier urlVerifier = new URLVerifier(publicKeyContents);

        byte[] message = "lorem impsum sit dolor jeff ament".getBytes();
        byte[] signature = urlSigner.getSignature(message);
        assertTrue(urlVerifier.getVerification(message, signature));

        byte[] wrongMessage = message.clone();
        wrongMessage[1] = 'f';
        assertFalse(urlVerifier.getVerification(wrongMessage, signature));
    }
}