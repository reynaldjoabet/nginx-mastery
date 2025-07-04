import java.security.Provider
import de.dentrassi.crypto.pem.PemKeyStoreProvider;
import java.security.Security
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.PrivateKey

object MainApp{

Security.addProvider(new PemKeyStoreProvider());


val email = "test@yugabyte.com"
     val issuer = "https://random-oidc-issuer.com"

     val  claimsSet =
         new JWTClaimsSet.Builder()
             .issuer(issuer)
             .claim("email", email)
             .claim("groups", List("Admin Group", "BackupAdmin Group"))
             .build()

     val generator = KeyPairGenerator.getInstance("RSA");
     generator.initialize(2048);
     val  keyPair: KeyPair = generator.generateKeyPair();
    val  privateKey: PrivateKey = keyPair.getPrivate();

     val  jwtToken =
         new SignedJWT(
             new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("keyID").build(), claimsSet);
     jwtToken.sign(new RSASSASigner(privateKey));
}