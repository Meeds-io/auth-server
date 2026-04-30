/**
 * This file is part of the Meeds project (https://meeds.io/).
 *
 * Copyright (C) 2020 - 2026 Meeds Association contact@meeds.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package io.meeds.oauth2.server.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.ORIGIN;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.meeds.oauth2.server.service.OAuthClientService;
import io.meeds.oauth2.server.service.OAuthSettingService;
import io.meeds.oauth2.server.service.OAuthTokenService;
import io.meeds.oauth2.server.test.OAuthServiceIntegrationTestSupport;

@AutoConfigureMockMvc
@DisplayName("OAuth2 security integration suite")
class OAuthSecurityIntegrationTest extends OAuthServiceIntegrationTestSupport {

  private static final String               SCOPE_PATH                       = "$.scope";

  private static final String               USERNAME                         = "root";

  private static final String               USERS_ROLE                       = "users";

  private static final String               ACCESS_TOKEN_PATH                = "$.access_token";

  private static final String               AS_METADATA_ENDPOINT             = "/.well-known/oauth-authorization-server";

  private static final String               OIDC_METADATA_ENDPOINT           = "/.well-known/openid-configuration";

  private static final String               AUTHORIZE_ENDPOINT               = "/oauth2/authorize";

  private static final String               TOKEN_ENDPOINT                   = "/oauth2/token";

  private static final String               INTROSPECTION_ENDPOINT           = "/oauth2/introspect";

  private static final String               JWKS_ENDPOINT                    = "/oauth2/jwks";

  private static final String               DCR_ENDPOINT                     = "/oauth2/register";

  private static final String               CLIENT_ORIGIN                    = "https://client.com";

  private static final String               REDIRECT_URI                     = CLIENT_ORIGIN + "/callback";

  private static final String               CODE_CHALLENGE_METHOD_PARAM      = "code_challenge_method";

  private static final String               CODE_CHALLENGE_PARAM             = "code_challenge";

  private static final String               STATE_PARAM                      = "state";

  private static final String               REDIRECT_URI_PARAM               = "redirect_uri";

  private static final String               CLIENT_ID_PARAM                  = "client_id";

  private static final String               RESPONSE_TYPE_PARAM              = "response_type";

  private static final String               SCOPE_PARAM                      = "scope";

  private static final String               TOKEN_ENDPOINT_AUTH_METHOD_PARAM = "token_endpoint_auth_method";

  private static final String               RESPONSE_TYPES_PARAM             = "response_types";

  private static final String               GRANT_TYPES_PARAM                = "grant_types";

  private static final String               REDIRECT_URIS_PARAM              = "redirect_uris";

  private static final String               CLIENT_NAME_PARAM                = "client_name";

  private static final String               RESOURCE_PARAM                   = "resource";

  private static final String               GRANT_TYPE_PARAM                 = "grant_type";

  private static final String               TOKEN_PARAM                      = "token";

  private static final String               ERROR_PATH                       = "$.error";

  private static final String               TOKEN_TYPE_PATH                  = "$.token_type";

  private static final String               ACTIVE_PATH                      = "$.active";

  private static final String               CLIENT_ID_PATH                   = "$.client_id";

  private static final String               CODE_VERIFIER                    =
                                                          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901234567890123456789";

  private static final String               CLIENT_SECRET_VALUE              = "secret";

  private static final String               BEARER_VALUE                     = "Bearer";

  private static final String               INVALID_TOKEN_ERROR              = "invalid_token";

  private static final int                  DCR_LIMIT_REQUESTS               = 10;

  private final ObjectMapper                objectMapper                     = new ObjectMapper();

  @Autowired
  private OAuthSettingService               oAuthSettingService;

  @Autowired
  private OAuthClientService                oAuthClientService;

  @Autowired
  private RegisteredClientRepository        registeredClientRepository;

  @Autowired
  private OAuthTokenService                 oAuthTokenService;

  @Autowired
  private OAuth2AuthorizationConsentService authorizationConsentService;

  @Autowired
  private PasswordEncoder                   passwordEncoder;

  @Autowired
  private MockMvc                           mvc;

  @BeforeEach
  @Override
  protected void setUp() {
    begin();
    seedSecuritySettings();
  }

  @Test
  @DisplayName("DCR accepts valid public client registration")
  void dcrAcceptsValidPublicClientRegistration() throws Exception {
    MvcResult result = mvc.perform(post(DCR_ENDPOINT).contentType(APPLICATION_JSON)
                                                     .content(toJson(dcrRegistration(List.of(REDIRECT_URI),
                                                                                     List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())))))
                          .andExpect(status().isCreated())
                          .andExpect(jsonPath(CLIENT_ID_PATH).isNotEmpty())
                          .andExpect(jsonPath("$.redirect_uris[0]").value(REDIRECT_URI))
                          .andExpect(jsonPath("$.token_endpoint_auth_method").value("none"))
                          .andReturn();
    JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
    assertThat(oAuthClientService.getClient(body.path(CLIENT_ID_PARAM).asText(), true)).isNotNull();
  }

  @Test
  @DisplayName("DCR rejects invalid redirect URI")
  void dcrRejectsInvalidRedirectUri() throws Exception {
    String redirectUri = CLIENT_ORIGIN + ".evil.com/callback";
    mvc.perform(post(DCR_ENDPOINT).contentType(APPLICATION_JSON)
                                  .content(toJson(dcrRegistration(List.of(redirectUri),
                                                                  List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())))))
       .andExpect(status().isUnauthorized())
       .andExpect(jsonPath(ERROR_PATH).value(INVALID_TOKEN_ERROR));
  }

  @Test
  @DisplayName("Authorization-server metadata exposes DCR and CIMD support")
  void metadataExposesRegistrationAndCimdSupport() throws Exception {
    mvc.perform(get(AS_METADATA_ENDPOINT))
       .andExpect(status().isOk())
       .andExpect(header().string(CONTENT_TYPE, containsString(APPLICATION_JSON.toString())))
       .andExpect(jsonPath("$.issuer").value(issuerUrl()))
       .andExpect(jsonPath("$.registration_endpoint").value(issuerUrl() + DCR_ENDPOINT))
       .andExpect(jsonPath("$.client_id_metadata_document_supported").value(true))
       .andExpect(jsonPath("$.authorization_endpoint").value(issuerUrl() + AUTHORIZE_ENDPOINT))
       .andExpect(jsonPath("$.token_endpoint").value(issuerUrl() + TOKEN_ENDPOINT))
       .andExpect(jsonPath("$.jwks_uri").value(issuerUrl() + JWKS_ENDPOINT));
  }

  @Test
  @DisplayName("OIDC discovery metadata does not expose internal URLs")
  void oidcMetadataDoesNotExposeInternalUrls() throws Exception {
    MvcResult result = mvc.perform(get(OIDC_METADATA_ENDPOINT))
                          .andExpect(status().isOk())
                          .andReturn();
    JsonNode metadata = objectMapper.readTree(result.getResponse().getContentAsString());

    assertThat(metadata.path("issuer").asText()).isEqualTo(issuerUrl());
    assertThat(metadata.path("jwks_uri").asText()).startsWith(issuerUrl());
    assertThat(metadata.toString()).doesNotContain("localhost", "127.0.0.1", "0.0.0.0", "file:");
  }

  @Test
  @DisplayName("Authorization endpoint rejects redirect URI bypass matrix")
  void authorizationEndpointRejectsRedirectBypassMatrix() throws Exception {
    RegisteredClient client = publicClient("registered-client-%s".formatted(UUID.randomUUID()), REDIRECT_URI);
    oAuthClientService.createClient(client);

    List<String> bypassCandidates = List.of(CLIENT_ORIGIN + ".evil.com/callback",
                                            CLIENT_ORIGIN + "@evil.com/callback",
                                            CLIENT_ORIGIN + "/callback/../evil",
                                            CLIENT_ORIGIN + "/callback%2f..%2fevil",
                                            CLIENT_ORIGIN + ":444/callback",
                                            CLIENT_ORIGIN + "/callback#fragment");

    for (String redirectUri : bypassCandidates) {
      mvc.perform(get(AUTHORIZE_ENDPOINT).param(RESPONSE_TYPE_PARAM, "code")
                                         .param(CLIENT_ID_PARAM, client.getClientId())
                                         .param(REDIRECT_URI_PARAM, redirectUri)
                                         .param(SCOPE_PARAM, OidcScopes.OPENID)
                                         .param(STATE_PARAM, getRandomState())
                                         .param(CODE_CHALLENGE_PARAM, "abcdefghijklmnopqrstuvwxyz012345678901234567890123456789")
                                         .param(CODE_CHALLENGE_METHOD_PARAM, "S256"))
         .andExpect(status().isBadRequest())
         .andExpect(header().doesNotExist(HttpHeaders.LOCATION));
    }
  }

  @Test
  @DisplayName("CORS allows exact configured origin")
  void corsAllowsExactConfiguredOrigin() throws Exception {
    mvc.perform(options(TOKEN_ENDPOINT).header(ORIGIN, CLIENT_ORIGIN)
                                       .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
       .andExpect(status().isForbidden())
       .andExpect(content().string("Invalid CORS request"));
  }

  @Test
  @DisplayName("CORS rejects origin prefix/suffix/default-port bypasses")
  void corsRejectsOriginBypassVariants() throws Exception {
    for (String origin : List.of(CLIENT_ORIGIN + ".evil.com",
                                 CLIENT_ORIGIN + ":443",
                                 CLIENT_ORIGIN + "/")) {
      mvc.perform(options(TOKEN_ENDPOINT).header(ORIGIN, origin)
                                         .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
         .andExpect(header().string(ACCESS_CONTROL_ALLOW_ORIGIN, not(origin)));
    }
  }

  @Test
  @DisplayName("Client Credentials Token Uses Default Client Audience")
  void clientCredentialsTokenUsesDefaultClientAudience() throws Exception {
    RegisteredClient client = confidentialOpaqueClient("audience-client-" + UUID.randomUUID(), CLIENT_SECRET_VALUE);
    registeredClientRepository.save(client);

    mvc.perform(post(TOKEN_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                    .header(AUTHORIZATION, basic(client.getClientId(), CLIENT_SECRET_VALUE))
                                    .param(GRANT_TYPE_PARAM, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                                    .param(SCOPE_PARAM, OidcScopes.OPENID)
                                    .param(RESOURCE_PARAM, "https://evil.example"))
       .andExpect(status().isOk())
       .andExpect(jsonPath(ACCESS_TOKEN_PATH).exists())
       .andExpect(jsonPath(TOKEN_TYPE_PATH).value(BEARER_VALUE));
  }

  @Test
  @DisplayName("JWKS endpoint exposes signing keys with stable kid values")
  void jwksEndpointExposesSigningKeys() throws Exception {
    Map<String, Object> firstResponse = getJwks();
    List<String> firstKids = kids(firstResponse);

    assertThat(firstKids).isNotEmpty();

    Map<String, Object> secondResponse = getJwks();
    List<String> secondKids = kids(secondResponse);

    assertThat(secondKids).isNotEmpty();
    assertThat(secondKids).containsAnyElementsOf(firstKids);
    assertThat(secondKids).doesNotHaveDuplicates();
  }

  @Test
  @DisplayName("DCR rate limiter rejects request after configured boundary")
  void dcrRateLimiterRejectsAfterConfiguredBoundary() throws Exception {
    for (int i = 0; i < DCR_LIMIT_REQUESTS + 2; i++) {
      int index = i;
      String redirectUri = CLIENT_ORIGIN + "/callback/rate-%s".formatted(UUID.randomUUID());
      mvc.perform(post(DCR_ENDPOINT).contentType(APPLICATION_JSON)
                                    .content(toJson(dcrRegistration(List.of(redirectUri),
                                                                    List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())))))
         .andExpect(result -> {
           if (index < DCR_LIMIT_REQUESTS) {
             assertThat(result.getResponse().getStatus()).isIn(201, 401);
           } else {
             assertThat(result.getResponse().getStatus()).isEqualTo(401);
           }
         })
         .andReturn();
    }

    String redirectUri = CLIENT_ORIGIN + "/callback/rate-overflow-%s".formatted(UUID.randomUUID());
    mvc.perform(post(DCR_ENDPOINT).contentType(APPLICATION_JSON)
                                  .content(toJson(dcrRegistration(List.of(redirectUri),
                                                                  List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())))))
       .andExpect(status().isUnauthorized())
       .andExpect(jsonPath(ERROR_PATH).value(INVALID_TOKEN_ERROR));
  }

  @Test
  @DisplayName("DCR normalizes client_credentials request by adding authorization_code")
  void dcrNormalizesClientCredentialsRequestByAddingAuthorizationCode() throws Exception {
    String redirectUri = CLIENT_ORIGIN + "/callback/client-credentials-" + UUID.randomUUID();

    mvc.perform(post(DCR_ENDPOINT).contentType(APPLICATION_JSON)
                                  .content(toJson(dcrRegistration(
                                                                  List.of(redirectUri),
                                                                  List.of(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())))))
       .andExpect(status().isCreated())
       .andExpect(jsonPath("$.grant_types").value(hasItem(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())))
       .andExpect(jsonPath("$.grant_types").value(hasItem(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())));
  }

  @Test
  @DisplayName("DCR rejects multiple redirect base URIs")
  void dcrRejectsMultipleRedirectBaseUris() throws Exception {
    mvc.perform(post(DCR_ENDPOINT).contentType(APPLICATION_JSON)
                                  .content(toJson(dcrRegistration(
                                                                  List.of(REDIRECT_URI, "https://other-client.com/callback"),
                                                                  List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())))))
       .andExpect(status().isUnauthorized())
       .andExpect(jsonPath(ERROR_PATH).value(INVALID_TOKEN_ERROR));
  }

  @Test
  @DisplayName("DCR accepts empty scope and applies server defaults")
  void dcrAcceptsEmptyScopeAndAppliesDefaultScopes() throws Exception {
    Map<String, Object> request = dcrRegistration(List.of(REDIRECT_URI),
                                                  List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()));
    request.remove(SCOPE_PARAM);

    mvc.perform(post(DCR_ENDPOINT)
                                  .contentType(APPLICATION_JSON)
                                  .content(toJson(request)))
       .andExpect(status().isCreated())
       .andExpect(jsonPath(SCOPE_PATH).value(containsString(OidcScopes.OPENID)));
  }

  @Test
  @DisplayName("Metadata exposes none token endpoint auth method")
  void metadataExposesNoneTokenEndpointAuthMethod() throws Exception {
    mvc.perform(get(AS_METADATA_ENDPOINT))
       .andExpect(status().isOk())
       .andExpect(jsonPath("$.token_endpoint_auth_methods_supported").isArray())
       .andExpect(jsonPath("$.token_endpoint_auth_methods_supported").value(hasItem("none")));
  }

  @Test
  @DisplayName("Token endpoint rejects invalid client credentials")
  void tokenEndpointRejectsInvalidClientCredentials() throws Exception {
    RegisteredClient client = confidentialOpaqueClient("bad-secret-client-" + UUID.randomUUID(), CLIENT_SECRET_VALUE);
    registeredClientRepository.save(client);

    mvc.perform(post(TOKEN_ENDPOINT)
                                    .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                    .header(AUTHORIZATION, basic(client.getClientId(), "wrong-secret"))
                                    .param(GRANT_TYPE_PARAM, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                                    .param(SCOPE_PARAM, OidcScopes.OPENID))
       .andExpect(status().isUnauthorized())
       .andExpect(jsonPath(ERROR_PATH).value("invalid_client"));
  }

  @Test
  @DisplayName("Token endpoint rejects unsupported grant type")
  void tokenEndpointRejectsUnsupportedGrantType() throws Exception {
    RegisteredClient client = confidentialOpaqueClient("unsupported-grant-client-" + UUID.randomUUID(), CLIENT_SECRET_VALUE);
    registeredClientRepository.save(client);

    mvc.perform(post(TOKEN_ENDPOINT)
                                    .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                    .header(AUTHORIZATION, basic(client.getClientId(), CLIENT_SECRET_VALUE))
                                    .param(GRANT_TYPE_PARAM, "password")
                                    .param("username", USERNAME)
                                    .param("password", CLIENT_SECRET_VALUE))
       .andExpect(status().isBadRequest())
       .andExpect(jsonPath(ERROR_PATH).exists());
  }

  @Test
  @DisplayName("JWKS entries expose signing use, kid, kty and alg")
  void jwksEntriesExposeRequiredPublicKeyFields() throws Exception {
    Map<String, Object> jwks = getJwks();

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");

    assertThat(keys).isNotEmpty();
    keys.forEach(key -> {
      assertThat(key).containsKeys("kid", "kty", "alg", "use");
      assertThat(key.get("use")).isEqualTo("sig");
      assertThat(key.get("kty")).isEqualTo("RSA");
    });
  }

  @Test
  @DisplayName("Settings reject invalid allowed redirect URI prefix")
  void settingsRejectInvalidAllowedRedirectUriPrefix() {
    String redirectUri = CLIENT_ORIGIN + "@evil.com/callback";
    assertThatThrownBy(() -> oAuthSettingService.addAllowedRedirectUri(redirectUri)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("Client credentials access token is opaque")
  void clientCredentialsAccessTokenIsOpaque() throws Exception {
    RegisteredClient client = confidentialOpaqueClient("opaque-client-" + UUID.randomUUID(), CLIENT_SECRET_VALUE);
    registeredClientRepository.save(client);

    MvcResult result = mvc.perform(post(TOKEN_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                                       .header(AUTHORIZATION, basic(client.getClientId(), CLIENT_SECRET_VALUE))
                                                       .param(GRANT_TYPE_PARAM,
                                                              AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                                                       .param(SCOPE_PARAM, OidcScopes.OPENID))
                          .andExpect(status().isOk())
                          .andExpect(jsonPath(ACCESS_TOKEN_PATH).exists())
                          .andExpect(jsonPath(TOKEN_TYPE_PATH).value(BEARER_VALUE))
                          .andReturn();

    String accessToken = objectMapper.readTree(result.getResponse().getContentAsString())
                                     .path("access_token")
                                     .asText();

    assertThat(accessToken).isNotBlank();
    String[] parts = accessToken.split("\\.");
    assertThat(parts.length).isEqualTo(1);
  }

  @Test
  @DisplayName("Introspection returns active true for valid opaque access token")
  void introspectionReturnsActiveTrueForValidOpaqueAccessToken() throws Exception {
    RegisteredClient client = confidentialOpaqueClient("introspect-client-" + UUID.randomUUID(), CLIENT_SECRET_VALUE);
    registeredClientRepository.save(client);

    String token = issueClientCredentialsToken(client);
    mvc.perform(post(INTROSPECTION_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                            .header(AUTHORIZATION, basic(client.getClientId(), CLIENT_SECRET_VALUE))
                                            .param(TOKEN_PARAM, token))
       .andExpect(status().isOk())
       .andExpect(jsonPath(ACTIVE_PATH).value(true))
       .andExpect(jsonPath(CLIENT_ID_PATH).value(client.getClientId()))
       .andExpect(jsonPath(TOKEN_TYPE_PATH).value(BEARER_VALUE))
       .andExpect(jsonPath(SCOPE_PATH).value(containsString(OidcScopes.OPENID)))
       .andExpect(jsonPath("$.exp").exists())
       .andExpect(jsonPath("$.iat").exists());
  }

  @Test
  @DisplayName("Introspection returns active false for removed access token")
  void introspectionInactiveAfterTokenRemoval() throws Exception {
    RegisteredClient client = confidentialOpaqueClient("introspect-client-" + UUID.randomUUID(), CLIENT_SECRET_VALUE);
    registeredClientRepository.save(client);

    String token = issueClientCredentialsToken(client);
    oAuthTokenService.deleteTokensByClient(client.getClientId());

    mvc.perform(post(INTROSPECTION_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                            .header(AUTHORIZATION, basic(client.getClientId(), CLIENT_SECRET_VALUE))
                                            .param(TOKEN_PARAM, token))
       .andExpect(status().isOk())
       .andExpect(jsonPath(ACTIVE_PATH).value(false));
  }

  @Test
  @DisplayName("Introspection endpoint is exposed")
  void introspectionEndpointIsExposed() throws Exception {
    mvc.perform(post(INTROSPECTION_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                            .param(TOKEN_PARAM, "dummy"))
       .andExpect(status().is3xxRedirection())
       .andExpect(header().string(HttpHeaders.LOCATION, containsString("/portal/login")));
  }

  @Test
  @DisplayName("Introspection returns active false for unknown token")
  void introspectionReturnsActiveFalseForUnknownToken() throws Exception {
    RegisteredClient client = confidentialOpaqueClient("introspect-invalid-client-" + UUID.randomUUID(), CLIENT_SECRET_VALUE);
    registeredClientRepository.save(client);
    mvc.perform(post(INTROSPECTION_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                            .header(AUTHORIZATION, basic(client.getClientId(), CLIENT_SECRET_VALUE))
                                            .param(TOKEN_PARAM, "unknown-" + UUID.randomUUID()))
       .andExpect(status().isOk())
       .andExpect(jsonPath(ACTIVE_PATH).value(false));
  }

  @Test
  @DisplayName("Introspection rejects invalid client authentication")
  void introspectionRejectsInvalidClientAuth() throws Exception {
    mvc.perform(post(INTROSPECTION_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                            .header(AUTHORIZATION, basic("bad", "bad"))
                                            .param(TOKEN_PARAM, "whatever"))
       .andExpect(status().isUnauthorized());
  }

  @Test
  @DisplayName("Public client completes authorization code flow with PKCE")
  void publicClientCompletesAuthorizationCodeFlowWithPkce() throws Exception {
    String redirectUri = CLIENT_ORIGIN + "/callback/pkce-" + UUID.randomUUID();

    RegisteredClient client = publicClient("pkce-client-" + UUID.randomUUID(), redirectUri);
    oAuthClientService.createClient(client);

    String codeChallenge = s256(CODE_VERIFIER);
    String state = getRandomState();

    grantConsent(client, USERNAME, OidcScopes.OPENID);

    MvcResult authorizeResult = mvc.perform(get(AUTHORIZE_ENDPOINT).with(user(USERNAME).roles(USERS_ROLE))
                                                                   .queryParam(RESPONSE_TYPE_PARAM, "code")
                                                                   .queryParam(CLIENT_ID_PARAM, client.getClientId())
                                                                   .queryParam(REDIRECT_URI_PARAM, redirectUri)
                                                                   .queryParam(SCOPE_PARAM, OidcScopes.OPENID)
                                                                   .queryParam(STATE_PARAM, state)
                                                                   .queryParam(CODE_CHALLENGE_PARAM, codeChallenge)
                                                                   .queryParam(CODE_CHALLENGE_METHOD_PARAM, "S256"))
                                   .andExpect(status().is3xxRedirection())
                                   .andExpect(header().string(HttpHeaders.LOCATION, containsString(redirectUri)))
                                   .andReturn();

    String location = authorizeResult.getResponse().getHeader(HttpHeaders.LOCATION);
    Map<String, String> query = queryParams(location);

    assertThat(query.get(STATE_PARAM)).isEqualTo(state);

    assertThat(query).containsKey("code");
    String code = query.get("code");
    assertNotNull(code);

    mvc.perform(post(TOKEN_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                    .param(GRANT_TYPE_PARAM, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                                    .param("code", code)
                                    .param(REDIRECT_URI_PARAM, redirectUri)
                                    .param(CLIENT_ID_PARAM, client.getClientId())
                                    .param("code_verifier", CODE_VERIFIER))
       .andExpect(status().isOk())
       .andExpect(jsonPath(ACCESS_TOKEN_PATH).exists())
       .andExpect(jsonPath(TOKEN_TYPE_PATH).value(BEARER_VALUE));
  }

  @Test
  @DisplayName("Public client authorization code exchange rejects invalid PKCE verifier")
  void publicClientAuthorizationCodeExchangeRejectsInvalidPkceVerifier() throws Exception {
    String redirectUri = CLIENT_ORIGIN + "/callback/pkce-missing-" + UUID.randomUUID();

    RegisteredClient client = publicClient("pkce-missing-client-" + UUID.randomUUID(), redirectUri);
    oAuthClientService.createClient(client);

    grantConsent(client, USERNAME, OidcScopes.OPENID);

    String codeChallenge = s256(CODE_VERIFIER);
    String state = getRandomState();

    MvcResult result = mvc.perform(get(AUTHORIZE_ENDPOINT).with(user(USERNAME).roles(USERS_ROLE))
                                                          .queryParam(RESPONSE_TYPE_PARAM, "code")
                                                          .queryParam(CLIENT_ID_PARAM, client.getClientId())
                                                          .queryParam(REDIRECT_URI_PARAM, redirectUri)
                                                          .queryParam(SCOPE_PARAM, OidcScopes.OPENID)
                                                          .queryParam(STATE_PARAM, state)
                                                          .queryParam(CODE_CHALLENGE_PARAM, codeChallenge)
                                                          .queryParam(CODE_CHALLENGE_METHOD_PARAM, "S256"))
                          .andExpect(status().is3xxRedirection())
                          .andReturn();

    String code = queryParams(result.getResponse().getHeader(HttpHeaders.LOCATION)).get("code");

    mvc.perform(post(TOKEN_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                    .param(GRANT_TYPE_PARAM, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                                    .param(REDIRECT_URI_PARAM, redirectUri)
                                    .param(CLIENT_ID_PARAM, client.getClientId())
                                    .param("code", code)
                                    .param("code_verifier", "invalid-verifier"))
       .andExpect(status().isBadRequest())
       .andExpect(jsonPath(ERROR_PATH).exists());
  }

  @Test
  @DisplayName("Mistral DCR confidential registration returns deterministic reusable client secret")
  void mistralDcrConfidentialRegistrationReturnsDeterministicReusableClientSecret() throws Exception {
    String redirectUri = CLIENT_ORIGIN + "/callback/mistral-" + UUID.randomUUID();

    Map<String, Object> request = dcrRegistration(List.of(redirectUri),
                                                  List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
                                                          AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()));

    request.put(TOKEN_ENDPOINT_AUTH_METHOD_PARAM, ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());

    MvcResult firstResult = mvc.perform(post(DCR_ENDPOINT).contentType(APPLICATION_JSON)
                                                          .content(toJson(request)))
                               .andExpect(status().isCreated())
                               .andExpect(jsonPath(CLIENT_ID_PATH).isNotEmpty())
                               .andExpect(jsonPath("$.client_secret").isNotEmpty())
                               .andExpect(jsonPath("$.token_endpoint_auth_method")
                                                                                  .value(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()))
                               .andReturn();

    JsonNode firstBody = objectMapper.readTree(firstResult.getResponse().getContentAsString());
    String clientId = firstBody.path(CLIENT_ID_PARAM).asText();
    String clientSecret = firstBody.path("client_secret").asText();

    MvcResult secondResult = mvc.perform(post(DCR_ENDPOINT)
                                                           .contentType(APPLICATION_JSON)
                                                           .content(toJson(request)))
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath(CLIENT_ID_PATH).value(clientId))
                                .andExpect(jsonPath("$.client_secret").value(clientSecret))
                                .andReturn();

    JsonNode secondBody = objectMapper.readTree(secondResult.getResponse().getContentAsString());
    assertThat(secondBody.path("client_secret").asText()).isEqualTo(clientSecret);

    mvc.perform(post(TOKEN_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                    .header(AUTHORIZATION, basic(clientId, clientSecret))
                                    .param(GRANT_TYPE_PARAM, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                                    .param(SCOPE_PARAM, OidcScopes.OPENID))
       .andExpect(status().isOk())
       .andExpect(jsonPath(ACCESS_TOKEN_PATH).exists())
       .andExpect(jsonPath(TOKEN_TYPE_PATH).value(BEARER_VALUE));
  }

  private String s256(String verifier) throws Exception { // NOSONAR
    byte[] digest = MessageDigest.getInstance("SHA-256")
                                 .digest(verifier.getBytes(StandardCharsets.US_ASCII));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
  }

  private Map<String, String> queryParams(String location) {
    String query = URI.create(location).getRawQuery();
    return Arrays.stream(query.split("&"))
                 .map(pair -> pair.split("=", 2))
                 .collect(Collectors.toMap(pair -> urlDecode(pair[0]),
                                           pair -> pair.length > 1 ? urlDecode(pair[1]) : ""));
  }

  private String urlDecode(String value) {
    return URLDecoder.decode(value, StandardCharsets.UTF_8);
  }

  private void grantConsent(RegisteredClient client, String username, String... scopes) {
    OAuth2AuthorizationConsent.Builder consent =
                                               OAuth2AuthorizationConsent.withId(client.getId(), username);

    for (String scope : scopes) {
      consent.authority(new SimpleGrantedAuthority("SCOPE_" + scope));
    }

    authorizationConsentService.save(consent.build());
  }

  private void seedSecuritySettings() {
    oAuthSettingService.setAllowAllRedirectUris(false);
    oAuthSettingService.setAllowAllOrigins(false);
    addAllowedRedirectUriIfMissing(REDIRECT_URI);
    addAllowedOriginIfMissing(CLIENT_ORIGIN);
  }

  private void addAllowedRedirectUriIfMissing(String redirectUriPrefix) {
    if (!oAuthSettingService.getAllowedRedirectUris().contains(redirectUriPrefix)) {
      oAuthSettingService.addAllowedRedirectUri(redirectUriPrefix);
    }
  }

  private void addAllowedOriginIfMissing(String origin) {
    if (!oAuthSettingService.getAllowedOrigins().contains(origin)) {
      oAuthSettingService.addAllowedOrigin(origin);
    }
  }

  private String issuerUrl() {
    return oAuthSettingService.getIssuerUrl();
  }

  private RegisteredClient publicClient(String clientId, String redirectUri) {
    return RegisteredClient.withId(clientId)
                           .clientId(clientId)
                           .clientName("Test public client")
                           .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                           .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                           .redirectUri(redirectUri)
                           .scope(OidcScopes.OPENID)
                           .scope("profile")
                           .clientSettings(ClientSettings.builder()
                                                         .requireProofKey(true)
                                                         .requireAuthorizationConsent(true)
                                                         .build())
                           .tokenSettings(TokenSettings.builder()
                                                       .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                                                       .accessTokenTimeToLive(Duration.ofMinutes(5))
                                                       .refreshTokenTimeToLive(Duration.ofHours(1))
                                                       .build())
                           .build();
  }

  private RegisteredClient confidentialOpaqueClient(String clientId, String secret) {
    return RegisteredClient.withId(clientId)
                           .clientId(clientId)
                           .clientSecret(passwordEncoder.encode(secret))
                           .clientName("Opaque token test client")
                           .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                           .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                           .scope(OidcScopes.OPENID)
                           .clientSettings(ClientSettings.builder().build())
                           .tokenSettings(TokenSettings.builder()
                                                       .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                                                       .accessTokenTimeToLive(Duration.ofMinutes(5))
                                                       .build())
                           .build();
  }

  private Map<String, Object> dcrRegistration(List<String> redirectUris, List<String> grantTypes) {
    Map<String, Object> request = new LinkedHashMap<>();
    request.put(CLIENT_NAME_PARAM, "security-suite-" + UUID.randomUUID());
    request.put(REDIRECT_URIS_PARAM, redirectUris);
    request.put(GRANT_TYPES_PARAM, grantTypes);
    request.put(RESPONSE_TYPES_PARAM, List.of("code"));
    request.put(SCOPE_PARAM, "openid offline_access");
    request.put(TOKEN_ENDPOINT_AUTH_METHOD_PARAM, "none");
    return request;
  }

  private Map<String, Object> getJwks() throws Exception {
    MvcResult result = mvc.perform(get(JWKS_ENDPOINT))
                          .andExpect(status().isOk())
                          .andReturn();
    return objectMapper.readValue(result.getResponse().getContentAsString(), new TypeReference<>() {
    });
  }

  @SuppressWarnings("unchecked")
  private List<String> kids(Map<String, Object> jwks) {
    return ((List<Map<String, Object>>) jwks.get("keys")).stream()
                                                         .map(key -> (String) key.get("kid"))
                                                         .filter(kid -> kid != null && !kid.isBlank())
                                                         .toList();
  }

  private String basic(String clientId, String clientSecret) {
    return "Basic " + Base64.getEncoder()
                            .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
  }

  private String toJson(Object value) throws JsonProcessingException {
    return objectMapper.writeValueAsString(value);
  }

  private String issueClientCredentialsToken(RegisteredClient client) throws Exception {
    MvcResult result = mvc.perform(post(TOKEN_ENDPOINT).contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                                       .header(AUTHORIZATION, basic(client.getClientId(), CLIENT_SECRET_VALUE))
                                                       .param(GRANT_TYPE_PARAM,
                                                              AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                                                       .param(SCOPE_PARAM, OidcScopes.OPENID))
                          .andExpect(status().isOk())
                          .andReturn();

    return objectMapper.readTree(result.getResponse().getContentAsString())
                       .path("access_token")
                       .asText();
  }

  private String getRandomState() {
    return "state-" + UUID.randomUUID();
  }

}
