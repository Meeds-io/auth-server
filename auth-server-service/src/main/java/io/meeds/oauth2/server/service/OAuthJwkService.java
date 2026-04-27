package io.meeds.oauth2.server.service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import org.exoplatform.commons.api.settings.SettingService;
import org.exoplatform.commons.api.settings.SettingValue;
import org.exoplatform.commons.api.settings.data.Context;
import org.exoplatform.commons.api.settings.data.Scope;
import org.exoplatform.web.security.codec.CodecInitializer;

import io.meeds.oauth2.server.model.OAuthJwkSet;
import io.meeds.oauth2.server.model.OAuthJwkSet.OAuthJwkEntry;
import io.meeds.social.util.JsonUtils;

import lombok.SneakyThrows;
import lombok.Synchronized;

@Component
public class OAuthJwkService {

  private static final Context    JWKS_CONTEXT                 = Context.GLOBAL.id("meeds.oauth2.jwks");

  private static final Scope      JWKS_SCOPE                   = Scope.GLOBAL.id("jwks");

  private static final String     JWKS_KEY_V1                  = "jwks-v1";

  private static final String     JWKS_KEY_V2                  = "jwks-v2";

  private static final Duration   JWKS_ROTATION_PERIODIC_CHECK = Duration.ofDays(1);

  @Autowired
  private SettingService          settingService;

  @Autowired
  private CodecInitializer        codecInitializer;

  @Value("${meeds.oauth2.jwks.key-size:3072}")
  private int                     keySize;

  @Value("${meeds.oauth.public-client.token.authorization-code-time-to-live}")
  private Duration                authorizationCodeTimeToLiveDuration;

  @Value("${meeds.oauth.public-client.token.access-token-time-to-live}")
  private Duration                accessTokenTimeToLiveDuration;

  @Value("${meeds.oauth.public-client.token.refresh-token-time-to-live}")
  private Duration                refreshTokenTimeToLiveDuration;

  private AtomicReference<JWKSet> currentJwks                  = new AtomicReference<>();

  private Instant                 currentJwksInstant           = Instant.now();

  private Duration                jwksRotationDuration;

  @Synchronized
  public JWKSet getJwkSet() {
    JWKSet jwkSet = currentJwks.get();
    if (jwkSet == null
        || Duration.between(currentJwksInstant, Instant.now()).compareTo(JWKS_ROTATION_PERIODIC_CHECK) >= 0) {
      jwkSet = loadKeys();
      currentJwks.set(jwkSet);
      currentJwksInstant = Instant.now();
    }
    return jwkSet;
  }

  private JWKSet loadKeys() {
    List<OAuthJwkEntry> keys = getKeys().stream()
                                        .filter(k -> k.getActivatedAt()
                                                      .isAfter(Instant.now()
                                                                      .minusSeconds(getRotationDuration().getSeconds() * 2)))
                                        .toList();
    if (!hasActiveKeys(keys)) {
      JWKSet jwkSet = generateKeyPair();
      keys = new ArrayList<>(keys);
      keys.add(0,
               new OAuthJwkEntry(jwkSet.toString(false),
                                 Instant.now()));
      saveKeys(keys);
    }
    return new JWKSet(keys.stream()
                          .map(this::getKeyPair)
                          .filter(Objects::nonNull)
                          .map(JWKSet::getKeys)
                          .flatMap(List::stream)
                          .filter(Objects::nonNull)
                          .toList());
  }

  @SneakyThrows
  private List<OAuthJwkEntry> getKeys() {
    SettingValue<?> settingValue = settingService.get(JWKS_CONTEXT, JWKS_SCOPE, JWKS_KEY_V2);
    if (settingValue != null && settingValue.getValue() != null) {
      String keysString = codecInitializer.getCodec().decode(settingValue.getValue().toString());
      OAuthJwkSet oAuthJwkSet = JsonUtils.fromJsonString(keysString, OAuthJwkSet.class);
      return oAuthJwkSet.getEntries();
    } else {
      settingValue = settingService.get(JWKS_CONTEXT, JWKS_SCOPE, JWKS_KEY_V1);
      if (settingValue != null && settingValue.getValue() != null) {
        // Smooth Migration
        String jwksJson = codecInitializer.getCodec().decode(settingValue.getValue().toString());
        List<OAuthJwkEntry> keys = new ArrayList<>();
        keys.add(0,
                 new OAuthJwkEntry(jwksJson,
                                   Instant.now().minusSeconds(getRotationDuration().getSeconds() + 1)));
        saveKeys(keys);
        return keys;
      } else {
        return Collections.emptyList();
      }
    }
  }

  @SneakyThrows
  private void saveKeys(List<OAuthJwkEntry> keys) {
    String keysString = JsonUtils.toJsonString(new OAuthJwkSet(keys));
    String encodedKeysString = codecInitializer.getCodec().encode(keysString);
    settingService.set(JWKS_CONTEXT,
                       JWKS_SCOPE,
                       JWKS_KEY_V2,
                       SettingValue.create(encodedKeysString));
  }

  private boolean hasActiveKeys(List<OAuthJwkEntry> keys) {
    return keys.stream()
               .anyMatch(k -> k.getActivatedAt()
                               .isAfter(Instant.now()
                                               .minusSeconds(getRotationDuration().getSeconds())));
  }

  @SneakyThrows
  private JWKSet generateKeyPair() {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(keySize);
    KeyPair keyPair = generator.generateKeyPair();
    RSAKey.Builder rsaKeyBuilder = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic());
    RSAKey rsaKey = rsaKeyBuilder.privateKey((RSAPrivateKey) keyPair.getPrivate())
                                 .keyUse(KeyUse.SIGNATURE)
                                 .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                                 .keyID("sig-" + UUID.randomUUID())
                                 .build();
    return new JWKSet(rsaKey);
  }

  @SneakyThrows
  private JWKSet getKeyPair(OAuthJwkEntry e) {
    return JWKSet.parse(e.getKeyPairJson());
  }

  public Duration getRotationDuration() {
    if (jwksRotationDuration == null) {
      jwksRotationDuration = List.of(authorizationCodeTimeToLiveDuration,
                                     accessTokenTimeToLiveDuration,
                                     refreshTokenTimeToLiveDuration)
                                 .stream()
                                 .max(Duration::compareTo)
                                 .orElse(refreshTokenTimeToLiveDuration);
    }
    return jwksRotationDuration;
  }
}
