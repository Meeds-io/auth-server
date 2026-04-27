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

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_CREATION_DATE;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_ENABLED_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_IS_CIMD_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_IS_DCR_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SERVICE_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_SYSTEM_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_UUID_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CUSTOM_CLIENT_METADATA;
import static io.meeds.oauth2.server.util.OAuthEventType.CLIENT_REGISTER_REJECT_EVENT;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient.Builder;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import org.exoplatform.services.listener.ListenerService;
import org.exoplatform.web.security.codec.CodecInitializer;

import io.meeds.common.ContainerTransactional;
import io.meeds.oauth2.server.service.OAuthClientService;

import lombok.SneakyThrows;

/**
 * A Public Oauth clients Registration Handlers which will auto-register allowed
 * redirect URI(s) domain names
 */
public class OAuthDcrAuthenticationProvider implements AuthenticationProvider {

  public static final List<String>                              NON_PUBLIC_CLIENT_METADATA = List.of(CLIENT_CREATION_DATE,
                                                                                                     CLIENT_SYSTEM_SETTING,
                                                                                                     CLIENT_ENABLED_SETTING,
                                                                                                     CLIENT_SERVICE_SETTING,
                                                                                                     CLIENT_UUID_SETTING,
                                                                                                     CLIENT_IS_DCR_SETTING,
                                                                                                     CLIENT_IS_CIMD_SETTING);

  private final OAuthClientService                              oAuthClientService;

  private final CodecInitializer                                codecInitializer;

  private final PasswordEncoder                                 passwordEncoder;

  private final ListenerService                                 listenerService;

  private final OidcClientRegistrationRegisteredClientConverter registeredClientConverter;

  private final RegisteredClientOidcClientRegistrationConverter clientRegistrationConverter;

  private String                                                platformSecret;

  public OAuthDcrAuthenticationProvider(OAuthClientService oAuthClientService,
                                        CodecInitializer codecInitializer,
                                        PasswordEncoder passwordEncoder,
                                        ListenerService listenerService) {
    this.oAuthClientService = oAuthClientService;
    this.codecInitializer = codecInitializer;
    this.passwordEncoder = passwordEncoder;
    this.listenerService = listenerService;
    this.registeredClientConverter = new OidcClientRegistrationRegisteredClientConverter();
    this.clientRegistrationConverter = new RegisteredClientOidcClientRegistrationConverter();
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return OidcClientRegistrationAuthenticationToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    OidcClientRegistrationAuthenticationToken authenticationToken = (OidcClientRegistrationAuthenticationToken) authentication;
    return authenticate(authenticationToken);
  }

  @ContainerTransactional
  private Authentication authenticate(OidcClientRegistrationAuthenticationToken authenticationToken) { // NOSONAR
    OidcClientRegistration oidcClientRegistration = null;
    try {
      oidcClientRegistration = authenticationToken.getClientRegistration();
      RegisteredClient client = convert(oidcClientRegistration);
      RegisteredClient registeredClient = oAuthClientService.register(client);
      return new OidcClientRegistrationAuthenticationToken(authenticationToken,
                                                           convert(registeredClient));
    } catch (Exception e) {
      listenerService.broadcast(CLIENT_REGISTER_REJECT_EVENT, oidcClientRegistration, e);
      throw new AuthenticationServiceException(e.getMessage(), e);
    }
  }

  private RegisteredClient convert(OidcClientRegistration oidcClientRegistration) {
    RegisteredClient client = registeredClientConverter.convert(oidcClientRegistration);
    if (client == null) {
      throw new IllegalArgumentException("Client is mandatory");
    }
    Builder clientBuilder = RegisteredClient.from(client)
                                            .id(client.getClientId());
    if (ClientAuthenticationMethod.NONE.getValue().equals(oidcClientRegistration.getTokenEndpointAuthenticationMethod())) {
      clientBuilder.clientSecret(null);
      clientBuilder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
    } else if (StringUtils.isNotBlank(client.getClientSecret())) {
      clientBuilder.clientSecret(passwordEncoder.encode(generateSimulatedClientSecretForPublicClient(client)));
    }
    ClientSettings.Builder clientSettingsBuilder = ClientSettings.withSettings(client.getClientSettings().getSettings());
    oidcClientRegistration.getClaims()
                          .entrySet()
                          .stream()
                          .filter(e -> CUSTOM_CLIENT_METADATA.contains(e.getKey()))
                          .forEach(e -> clientSettingsBuilder.setting(e.getKey(), e.getValue()));
    return clientBuilder.clientSettings(clientSettingsBuilder.setting(CLIENT_IS_DCR_SETTING, true)
                                                             .build())
                        .build();
  }

  private OidcClientRegistration convert(RegisteredClient client) {
    ClientSettings clientSettings = client.getClientSettings();
    OidcClientRegistration oidcClientRegistration = clientRegistrationConverter.convert(client);
    Map<String, Object> claims = new HashMap<>(oidcClientRegistration.getClaims()); // NOSONAR
    NON_PUBLIC_CLIENT_METADATA.forEach(claims::remove);
    CUSTOM_CLIENT_METADATA.stream()
                          .filter(c -> clientSettings.getSetting(c) != null)
                          .forEach(c -> claims.put(c, clientSettings.getSetting(c)));
    OidcClientRegistration.Builder oidcClientRegistrationBuilder = OidcClientRegistration.withClaims(claims);
    if (StringUtils.isNotBlank(oidcClientRegistration.getClientSecret())) {
      oidcClientRegistrationBuilder.clientSecret(generateSimulatedClientSecretForPublicClient(client));
    }
    return oidcClientRegistrationBuilder.build();
  }

  /**
   * Used only for OAuth clients which doesn't support Public Clients This will
   * force a non support of Public clients to be supported By adding a fake
   * password which is deterinistic and will return the same each time the DCR
   * is invoked
   * 
   * @param client {@link RegisteredClient}
   * @return deterinistic password content from Registered Client
   */
  private String generateSimulatedClientSecretForPublicClient(RegisteredClient client) {
    return new HmacUtils(HmacAlgorithms.HMAC_SHA_256, getPlatformSecret()).hmacHex(client.getClientId());
  }

  @SneakyThrows
  public String getPlatformSecret() {
    if (platformSecret == null) {
      platformSecret = codecInitializer.getCodec().encode("oauth-public-client-platform-secret");
    }
    return platformSecret;
  }

}
