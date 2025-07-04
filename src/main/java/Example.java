
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.*;
import java.util.Date;
//import com.google.common.collect.ImmutableList;
import java.util.List;
class Example {
     

    public static void main(String[] args) throws Exception {
String email = "test@yugabyte.com";
String issuer = "https://random-oidc-issuer.com";
        JWTClaimsSet claimsSet =
            new JWTClaimsSet.Builder()
                .issuer(issuer)
                .claim("email", email)
                .claim("groups", List.of("Admin Group", "BackupAdmin Group"))
                .build();
//ImmutableList<String> groups = ImmutableList.of("Admin Group", "BackupAdmin Group");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        SignedJWT jwtToken =
            new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("keyID").build(), claimsSet);


        jwtToken.sign(new RSASSASigner(privateKey));

    JWTClaimsSet claimsSet2 = new JWTClaimsSet.Builder()
      .subject("joe")
      .expirationTime(new Date(1300819380 * 1000l))
      .claim("http://example.com/is_root", true)
      .build();

      System.out.println("JWT Token: " + jwtToken.serialize());
}


}
