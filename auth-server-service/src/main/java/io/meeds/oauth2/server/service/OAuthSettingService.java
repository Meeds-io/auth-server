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
package io.meeds.oauth2.server.service;

import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_CIMD_URIS_ALL_MODIFIED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_CIMD_URI_ADDED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_CIMD_URI_REMOVED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_ORIGINS_ALL_MODIFIED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_ORIGIN_ADDED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_ORIGIN_REMOVED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_REDIRECT_URIS_ALL_MODIFIED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_REDIRECT_URI_ADDED_EVENT;
import static io.meeds.oauth2.server.util.OAuthEventType.ALLOWED_REDIRECT_URI_REMOVED_EVENT;

import java.net.IDN;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerProperties.Client;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerProperties.Token;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import org.exoplatform.commons.api.settings.SettingService;
import org.exoplatform.commons.api.settings.SettingValue;
import org.exoplatform.commons.api.settings.data.Context;
import org.exoplatform.commons.api.settings.data.Scope;
import org.exoplatform.commons.utils.PropertyManager;
import org.exoplatform.services.listener.ListenerService;

import io.meeds.oauth2.server.configuration.model.OAuthDefaultSettings;
import io.meeds.oauth2.server.util.Utils;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class OAuthSettingService {

  private static final Context CONTEXT                    = Context.GLOBAL.id("meeds.oauth");

  private static final Scope   SCOPE                      = Scope.APPLICATION.id("oauth.client.registration");

  private static final String  ALLOWED_REDIRECT_URI_KEY   = "allowedRedirectUriPrefixes";

  private static final String  ALLOWED_CIMD_URI_KEY       = "allowedCimdUriPrefixes";

  private static final String  ALLOWED_ORIGINS_KEY        = "allowedOrigins";

  private static final String  ALLOW_ALL_REDIRECT_URI_KEY = "allowedAllRedirectUris";

  private static final String  ALLOW_ALL_CIMD_URI_KEY     = "allowedAllCimdUris";

  private static final String  ALLOW_ALL_ORIGIN_KEY       = "allowedAllOriginUris";

  @Autowired
  private OAuthDefaultSettings defaultSettings;

  @Autowired
  private SettingService       settingService;

  @Autowired
  private ListenerService      listenerService;

  private String               issuerUrl;

  private Set<String>          scopes;

  private Set<String>          allowedAudiences;

  @Value("${meeds.oauth.allow-all-redirect-uris:false}")
  private boolean              defaultAllowAllRedirectUris;

  @Value("${meeds.oauth.allow-all-cimd-uris:false}")
  private boolean              defaultAllowAllCimdUris;

  @Value("${meeds.oauth.allow-all-origins:false}")
  private boolean              defaultAllowAllOrigins;

  @Value("#{'${meeds.oauth.development-insecure-hosts:localhost,127.0.0.1}'.split(',')}")
  private List<String>         developmentAllowedInsecureHosts;

  public String getIssuerUrl() {
    if (issuerUrl == null) {
      issuerUrl = defaultSettings.getIssuerUrl()
                                 .replaceAll("([^:])//", "$1/")
                                 .replaceAll("/$", "");
    }
    return issuerUrl;
  }

  public Set<String> getScopes() {
    if (scopes == null) {
      scopes = PropertyManager.getProperties()
                              .entrySet()
                              .stream()
                              .filter(e -> e.getKey().toString().startsWith("meeds.oauth.app.scopes"))
                              .map(Entry::getValue)
                              .map(Object::toString)
                              .flatMap(s -> Arrays.stream(s.split(",")))
                              .filter(StringUtils::isNotBlank)
                              .map(String::trim)
                              .collect(Collectors.toCollection(LinkedHashSet::new));
      ((LinkedHashSet<String>) scopes).addFirst(OidcScopes.OPENID);
      ((LinkedHashSet<String>) scopes).add(Utils.OFFLINE_ACCESS_SCOPE);
    }
    return scopes;
  }

  public Set<String> getAllowedAudiences() {
    if (allowedAudiences == null) {
      allowedAudiences = PropertyManager.getProperties()
                                        .entrySet()
                                        .stream()
                                        .filter(e -> e.getKey().toString().startsWith("meeds.oauth.app.audiences"))
                                        .map(Entry::getValue)
                                        .map(Object::toString)
                                        .flatMap(s -> Arrays.stream(s.split(",")))
                                        .filter(StringUtils::isNotBlank)
                                        .map(String::trim)
                                        .collect(Collectors.toCollection(LinkedHashSet::new));
    }
    return allowedAudiences;
  }

  public List<String> getAllowedRedirectUris() {
    SettingValue<?> settingValue = settingService.get(CONTEXT, SCOPE, ALLOWED_REDIRECT_URI_KEY);
    if (settingValue == null || settingValue.getValue() == null) {
      return StringUtils.isBlank(defaultSettings.getAllowedRedirectUriPrefixes()) ? Collections.emptyList() :
                                                                                  Arrays.stream(defaultSettings.getAllowedRedirectUriPrefixes()
                                                                                                               .split(","))
                                                                                        .filter(StringUtils::isNotBlank)
                                                                                        .toList();
    } else {
      return Arrays.stream(settingValue.getValue()
                                       .toString()
                                       .split(","))
                   .filter(StringUtils::isNotBlank)
                   .toList();
    }
  }

  public List<String> getAllowedCimdUris() {
    SettingValue<?> settingValue = settingService.get(CONTEXT, SCOPE, ALLOWED_CIMD_URI_KEY);
    if (settingValue == null || settingValue.getValue() == null) {
      return StringUtils.isBlank(defaultSettings.getAllowedCimdUriPrefixes()) ? Collections.emptyList() :
                                                                              Arrays.stream(defaultSettings.getAllowedCimdUriPrefixes()
                                                                                                           .split(","))
                                                                                    .filter(StringUtils::isNotBlank)
                                                                                    .toList();
    } else {
      return Arrays.stream(settingValue.getValue()
                                       .toString()
                                       .split(","))
                   .filter(StringUtils::isNotBlank)
                   .toList();
    }
  }

  public List<String> getAllowedOrigins() {
    SettingValue<?> settingValue = settingService.get(CONTEXT, SCOPE, ALLOWED_ORIGINS_KEY);
    if (settingValue == null || settingValue.getValue() == null) {
      return StringUtils.isBlank(defaultSettings.getAllowedOrigins()) ? Collections.emptyList() :
                                                                      Arrays.stream(defaultSettings.getAllowedOrigins()
                                                                                                   .split(","))
                                                                            .filter(StringUtils::isNotBlank)
                                                                            .toList();
    } else {
      return Arrays.stream(settingValue.getValue()
                                       .toString()
                                       .split(","))
                   .filter(StringUtils::isNotBlank)
                   .toList();
    }
  }

  public boolean isAllowAllRedirectUris() {
    SettingValue<?> settingValue = settingService.get(CONTEXT, SCOPE, ALLOW_ALL_REDIRECT_URI_KEY);
    if (settingValue == null || settingValue.getValue() == null) {
      return defaultAllowAllRedirectUris;
    } else {
      return Boolean.parseBoolean(settingValue.getValue().toString());
    }
  }

  public boolean isAllowAllCimdUris() {
    SettingValue<?> settingValue = settingService.get(CONTEXT, SCOPE, ALLOW_ALL_CIMD_URI_KEY);
    if (settingValue == null || settingValue.getValue() == null) {
      return defaultAllowAllCimdUris;
    } else {
      return Boolean.parseBoolean(settingValue.getValue().toString());
    }
  }

  public boolean isAllowAllOrigins() {
    if (isAllowAllRedirectUris()) {
      return true;
    } else {
      SettingValue<?> settingValue = settingService.get(CONTEXT, SCOPE, ALLOW_ALL_ORIGIN_KEY);
      if (settingValue == null || settingValue.getValue() == null) {
        return defaultAllowAllOrigins;
      } else {
        return Boolean.parseBoolean(settingValue.getValue().toString());
      }
    }
  }

  public void setAllowAllRedirectUris(boolean allowAll) {
    settingService.set(CONTEXT, SCOPE, ALLOW_ALL_REDIRECT_URI_KEY, SettingValue.create(allowAll));
    listenerService.broadcast(ALLOWED_REDIRECT_URIS_ALL_MODIFIED_EVENT, allowAll, allowAll);
  }

  public void setAllowAllCimdUris(boolean allowAll) {
    settingService.set(CONTEXT, SCOPE, ALLOW_ALL_CIMD_URI_KEY, SettingValue.create(allowAll));
    listenerService.broadcast(ALLOWED_CIMD_URIS_ALL_MODIFIED_EVENT, allowAll, allowAll);
  }

  public void setAllowAllOrigins(boolean allowAll) {
    settingService.set(CONTEXT, SCOPE, ALLOW_ALL_ORIGIN_KEY, SettingValue.create(allowAll));
    listenerService.broadcast(ALLOWED_ORIGINS_ALL_MODIFIED_EVENT, allowAll, allowAll);
  }

  public void addAllowedRedirectUri(String redirectUriPrefix) {
    if (isUriStructureValid(redirectUriPrefix)) {
      List<String> allowedRedirectUris = new ArrayList<>(getAllowedRedirectUris());
      if (!allowedRedirectUris.contains(redirectUriPrefix.trim())) {
        allowedRedirectUris.add(redirectUriPrefix.trim());
        settingService.set(CONTEXT,
                           SCOPE,
                           ALLOWED_REDIRECT_URI_KEY,
                           SettingValue.create(StringUtils.join(allowedRedirectUris, ',')));
        listenerService.broadcast(ALLOWED_REDIRECT_URI_ADDED_EVENT, redirectUriPrefix, allowedRedirectUris);
      }
    } else {
      throw new IllegalArgumentException("Invalid URL Prefix Format. Must be https and must not have fragment nor userInfo.");
    }
  }

  public void addAllowedCimdUri(String cimdUriPrefix) {
    if (isUriStructureValid(cimdUriPrefix)) {
      List<String> allowedCimdUris = new ArrayList<>(getAllowedCimdUris());
      if (!allowedCimdUris.contains(cimdUriPrefix.trim())) {
        allowedCimdUris.add(cimdUriPrefix.trim());
        settingService.set(CONTEXT,
                           SCOPE,
                           ALLOWED_CIMD_URI_KEY,
                           SettingValue.create(StringUtils.join(allowedCimdUris, ',')));
        listenerService.broadcast(ALLOWED_CIMD_URI_ADDED_EVENT, cimdUriPrefix, allowedCimdUris);
      }
    } else {
      throw new IllegalArgumentException("Invalid URL Prefix Format. Must be https and must not have fragment nor userInfo.");
    }
  }

  public void addAllowedOrigin(String origin) {
    URI.create(origin); // URI Format Validation
    List<String> allowedOrigins = new ArrayList<>(getAllowedOrigins());
    if (!allowedOrigins.contains(origin.trim())) {
      allowedOrigins.add(origin.trim());
      settingService.set(CONTEXT,
                         SCOPE,
                         ALLOWED_ORIGINS_KEY,
                         SettingValue.create(StringUtils.join(allowedOrigins, ',')));
      listenerService.broadcast(ALLOWED_ORIGIN_ADDED_EVENT, origin, allowedOrigins);
    }
  }

  public void removeAllowedRedirectUri(String redirectUri) {
    List<String> allowedRedirectUris = new ArrayList<>(getAllowedRedirectUris());
    if (allowedRedirectUris.contains(redirectUri.trim())) {
      allowedRedirectUris.remove(redirectUri.trim());
      settingService.set(CONTEXT,
                         SCOPE,
                         ALLOWED_REDIRECT_URI_KEY,
                         SettingValue.create(StringUtils.join(allowedRedirectUris, ',')));
      listenerService.broadcast(ALLOWED_REDIRECT_URI_REMOVED_EVENT, redirectUri, allowedRedirectUris);
    }
  }

  public void removeAllowedCimdUri(String cimdUri) {
    List<String> allowedCimdUris = new ArrayList<>(getAllowedCimdUris());
    if (allowedCimdUris.contains(cimdUri.trim())) {
      allowedCimdUris.remove(cimdUri.trim());
      settingService.set(CONTEXT,
                         SCOPE,
                         ALLOWED_CIMD_URI_KEY,
                         SettingValue.create(StringUtils.join(allowedCimdUris, ',')));
      listenerService.broadcast(ALLOWED_CIMD_URI_REMOVED_EVENT, cimdUri, allowedCimdUris);
    }
  }

  public void removeAllowedOrigin(String origin) {
    List<String> allowedOrigins = new ArrayList<>(getAllowedOrigins());
    if (allowedOrigins.contains(origin.trim())) {
      allowedOrigins.remove(origin.trim());
      settingService.set(CONTEXT,
                         SCOPE,
                         ALLOWED_ORIGINS_KEY,
                         SettingValue.create(StringUtils.join(allowedOrigins, ',')));
      listenerService.broadcast(ALLOWED_ORIGIN_REMOVED_EVENT, origin, allowedOrigins);
    }
  }

  public ClientSettings getPublicClientSettings() {
    Client client = defaultSettings.getPublicClient();
    ClientSettings.Builder builder = ClientSettings.builder();
    PropertyMapper propertyMapper = PropertyMapper.get().alwaysApplyingWhenNonNull();
    propertyMapper.from(client::isRequireProofKey).to(builder::requireProofKey);
    propertyMapper.from(client::isRequireAuthorizationConsent).to(builder::requireAuthorizationConsent);
    propertyMapper.from(client::getJwkSetUri).to(builder::jwkSetUrl);
    propertyMapper.from(client::getTokenEndpointAuthenticationSigningAlgorithm)
                  .as(this::jwsAlgorithm)
                  .to(builder::tokenEndpointAuthenticationSigningAlgorithm);
    builder.requireAuthorizationConsent(true);
    builder.requireProofKey(true);
    return builder.build();
  }

  public TokenSettings getPublicClientTokenSettings() {
    Token token = defaultSettings.getPublicClient().getToken();
    TokenSettings.Builder builder = TokenSettings.builder();
    PropertyMapper propertyMapper = PropertyMapper.get().alwaysApplyingWhenNonNull();
    propertyMapper.from(token::getAuthorizationCodeTimeToLive).to(builder::authorizationCodeTimeToLive);
    propertyMapper.from(token::getAccessTokenTimeToLive).to(builder::accessTokenTimeToLive);
    propertyMapper.from(token::getDeviceCodeTimeToLive).to(builder::deviceCodeTimeToLive);
    propertyMapper.from(token::getRefreshTokenTimeToLive).to(builder::refreshTokenTimeToLive);
    propertyMapper.from(token::getAccessTokenFormat).as(OAuth2TokenFormat::new).to(builder::accessTokenFormat);
    propertyMapper.from(token::isReuseRefreshTokens).to(builder::reuseRefreshTokens);
    propertyMapper.from(token::getIdTokenSignatureAlgorithm)
                  .as(this::signatureAlgorithm)
                  .to(builder::idTokenSignatureAlgorithm);
    return builder.build();
  }

  private SignatureAlgorithm signatureAlgorithm(String signatureAlgorithm) {
    return SignatureAlgorithm.from(signatureAlgorithm.toUpperCase(Locale.ROOT));
  }

  private JwsAlgorithm jwsAlgorithm(String signingAlgorithm) {
    String name = signingAlgorithm.toUpperCase(Locale.ROOT);
    JwsAlgorithm jwsAlgorithm = SignatureAlgorithm.from(name);
    if (jwsAlgorithm == null) {
      jwsAlgorithm = MacAlgorithm.from(name);
    }
    return jwsAlgorithm;
  }

  public boolean isAllowedRedirectUri(String uri) {
    try {
      return isUriStructureValid(uri)
             && (isAllowAllRedirectUris()
                 || getAllowedRedirectUris().stream()
                                            .anyMatch(u -> isAllowedUriPrefix(u, uri)));
    } catch (Exception e) {
      log.warn("Error while validating Redirect URL: {}", uri, e);
      return false;
    }
  }

  public boolean isAllowedCimdUrl(String uri) {
    try {
      return isUriStructureValid(uri)
             && (isAllowAllCimdUris()
                 || getAllowedCimdUris().stream()
                                        .anyMatch(u -> isAllowedUriPrefix(u, uri)));
    } catch (Exception e) {
      log.warn("Error while validating CIMD URL: {}", uri, e);
      return false;
    }
  }

  private boolean isUriStructureValid(String uriPrefix) {
    URI uri = URI.create(uriPrefix).normalize();
    if (StringUtils.isBlank(uri.getScheme()) || StringUtils.isBlank(uri.getHost())) {
      return false;
    } else if (uri.getUserInfo() != null || uri.getFragment() != null) {
      return false;
    } else if ("https".equalsIgnoreCase(uri.getScheme().toLowerCase(Locale.ROOT))) {
      return true;
    } else {
      return PropertyManager.isDevelopping()
             && "http".equalsIgnoreCase(uri.getScheme())
             && developmentAllowedInsecureHosts.stream()
                                               .anyMatch(h -> h.equalsIgnoreCase(uri.getHost()));
    }
  }

  private boolean isAllowedUriPrefix(String allowedPrefix, String candidateUri) {
    URI allowed = URI.create(allowedPrefix).normalize();
    URI candidate = URI.create(candidateUri).normalize();
    if (!StringUtils.equalsIgnoreCase(allowed.getScheme(), candidate.getScheme())) {
      return false;
    } else if (!StringUtils.equals(normalizeHost(allowed.getHost()), normalizeHost(candidate.getHost()))) {
      return false;
    } else if (allowed.getUserInfo() != null || candidate.getUserInfo() != null) {
      return false;
    } else if (candidate.getFragment() != null) {
      return false;
    } else if (normalizePort(allowed) != normalizePort(candidate)) {
      return false;
    } else {
      String allowedPath = normalizePathPrefix(allowed.getPath());
      String candidatePath = normalizePathPrefix(candidate.getPath());
      // Avoid human intervention while allowing only approved redirect domains
      // Thus, the Path can be a non-empty prefix and not only exact match
      // like /path/to/callback/ is valid for
      // /path/to/callback/ANY_SUFFIX_OR_USER_DASHBOARD_ID
      return candidatePath.equals(allowedPath)
             || candidatePath.startsWith(allowedPath);
    }
  }

  private int normalizePort(URI uri) {
    if (uri.getPort() != -1) {
      return uri.getPort();
    }
    if ("https".equalsIgnoreCase(uri.getScheme())) {
      return 443;
    }
    if ("http".equalsIgnoreCase(uri.getScheme())) {
      return 80;
    }
    return -1;
  }

  private String normalizeHost(String host) {
    return host == null ? null : IDN.toASCII(host, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
  }

  private String normalizePathPrefix(String path) {
    if (StringUtils.isBlank(path)) {
      return "/";
    }
    String normalized = URI.create(path).normalize().getPath();
    return normalized.endsWith("/") ? normalized : normalized + "/";
  }

}
