package tw.noah.jwt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;

@Log4j2
@Service
public class TeamsJwtDemo implements ApplicationRunner {

    // microsoft reference document : https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens#validate-tokens
    private final String msOpenIdConfigureUrl = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";

    private ObjectMapper objectMapper = new ObjectMapper();

    @SneakyThrows
    public void run(ApplicationArguments args) {
        // token from teams http header: Authorization
        String token = "XXXXXXXXXX";
        String[] jwt = token.split("\\.");

        String header = new String(Base64.getUrlDecoder().decode(jwt[0]));
        String payload = new String(Base64.getUrlDecoder().decode(jwt[1]));
        String signature = new String(Base64.getUrlDecoder().decode(jwt[2]));

        String headerKid = objectMapper.readValue(header, new TypeReference<Map<String, Object>>() {}).get("kid").toString();

        HttpClient client = HttpClient.newBuilder().build();
        HttpRequest metaRequest = HttpRequest.newBuilder().uri(URI.create(msOpenIdConfigureUrl)).build();
        HttpResponse<String> metaResponse = client.send(metaRequest, HttpResponse.BodyHandlers.ofString());
        if (metaResponse.statusCode() < 200 || metaResponse.statusCode() >= 400) {
            throw new RuntimeException("Get meta data failed!");
        }
        Map<String, Object> metaMap = objectMapper.readValue(metaResponse.body(), new TypeReference<Map<String, Object>>() {});
        if (! metaMap.containsKey("jwks_uri")){
            throw new RuntimeException("Key url not found!");
        }
        String keyUrl = metaMap.get("jwks_uri").toString();
        log.info("keyUrl={}", keyUrl);

        HttpRequest keyRequest = HttpRequest.newBuilder().uri(URI.create(keyUrl)).build();
        HttpResponse<String> keyResponse = client.send(keyRequest, HttpResponse.BodyHandlers.ofString());
        if (keyResponse.statusCode() < 200 || keyResponse.statusCode() >= 400) {
            throw new RuntimeException("Get public key failed!");
        }
        log.info("keyResponse.body()={}", keyResponse.body());
        Keys keys = objectMapper.readValue(keyResponse.body(), Keys.class);
        Key key = Arrays.stream(keys.getKeys()).filter(f -> f.kid.equals(headerKid)).findFirst().orElseThrow(() -> new RuntimeException("key not found"));


        log.info("header={}", header);
        log.info("payload={}", payload);
        log.info("signature={}", signature);

        BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(key.n));
        BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(key.e));

        try {
            Jwts.parserBuilder().setSigningKey(KeyFactory.getInstance(key.kty).generatePublic(new RSAPublicKeySpec(modulus, exponent))).build().parseClaimsJws(token).getBody();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            log.error(ex, ex);
            // 驗證失敗，資料被竄改
        }

    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    static class Keys{
        private Key[] keys;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    static class Key{
        private String kty;
        private String use;
        private String kid;
        private String x5t;
        private String n;
        private String e;
        private String[] x5c;
        private String issuer;
    }

}
