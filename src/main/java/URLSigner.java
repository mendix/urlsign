import org.apache.http.client.utils.URIBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

public class URLSigner {

    public static final String URL_EXPIRE = "expire";
    public static final String URL_SIGNATURE = "signature";
    private static final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");

    private static PrivateKey key;
    private static Signature signature;

    public URLSigner(byte[] privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        this(KeyImporter.importPrivateKey(privateKey));
    }

    public URLSigner(String privateKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchProviderException {
        this(KeyImporter.importPrivateKey(privateKey));
    }

    public URLSigner(File privateKeyFile) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchProviderException {
        this(KeyImporter.importPrivateKey(privateKeyFile));
    }

    private URLSigner(PrivateKey privateKey) {
        key = privateKey;

        try {
            signature = Signature.getInstance("SHA1withRSA/ISO9796-2", BouncyCastleProvider.PROVIDER_NAME);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public URI sign(URI uri, int ttlInSeconds) throws SignatureException, URISyntaxException, InvalidKeyException {
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date timestampNow = new Date();
        Date timestampExpiry = new Date(timestampNow.getTime() + (TimeUnit.SECONDS.toMillis(ttlInSeconds)));

        String expiryValue = dateFormat.format(timestampExpiry);
        URIBuilder uriBuilder = new URIBuilder(uri);
        uriBuilder.addParameter(URL_EXPIRE, expiryValue);

        String uriToSign = uriBuilder.build().toString();
        byte[] signature = getSignature(uriToSign.getBytes());

        String signatureValue = DatatypeConverter.printBase64Binary(signature);
        uriBuilder.addParameter(URL_SIGNATURE, signatureValue);

        return uriBuilder.build();
    }

    public byte[] getSignature(byte[] message) throws SignatureException, InvalidKeyException {
        signature.initSign(key);
        signature.update(message);
        return signature.sign();
    }
}
