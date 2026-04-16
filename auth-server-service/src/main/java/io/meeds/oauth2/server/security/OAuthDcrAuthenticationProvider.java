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

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_IS_DCR_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CUSTOM_CLIENT_METADATA;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient.Builder;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import io.meeds.common.ContainerTransactional;
import io.meeds.oauth2.server.service.OAuthClientService;
import io.meeds.oauth2.server.service.OAuthPasswordEncoder;

import lombok.SneakyThrows;

/**
 * A Public Oauth clients Registration Handlers which will auto-register allowed
 * redirect URI(s) domain names
 */
public class OAuthDcrAuthenticationProvider implements AuthenticationProvider {

  private final OAuthClientService                                  oAuthClientService;

  private final OAuthPasswordEncoder                                passwordEncoder;

  private final Converter<OidcClientRegistration, RegisteredClient> registeredClientConverter;

  private final Converter<RegisteredClient, OidcClientRegistration> clientRegistrationConverter;

  public OAuthDcrAuthenticationProvider(OAuthClientService oAuthClientService,
                                        OAuthPasswordEncoder passwordEncoder) {
    this.oAuthClientService = oAuthClientService;
    this.passwordEncoder = passwordEncoder;
    this.registeredClientConverter = new OidcClientRegistrationRegisteredClientConverter();
    this.clientRegistrationConverter = new RegisteredClientOidcClientRegistrationConverter();
  }

  @Override
  @SneakyThrows
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    OidcClientRegistrationAuthenticationToken authenticationToken = (OidcClientRegistrationAuthenticationToken) authentication;
    return authenticate(authenticationToken);
  }

  @ContainerTransactional
  private Authentication authenticate(OidcClientRegistrationAuthenticationToken authenticationToken) {
    OidcClientRegistration oidcClientRegistration = authenticationToken.getClientRegistration();
    RegisteredClient client = convert(oidcClientRegistration);

    RegisteredClient registeredClient = oAuthClientService.register(client);
    return new OidcClientRegistrationAuthenticationToken(authenticationToken,
                                                         convert(registeredClient));
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return OidcClientRegistrationAuthenticationToken.class.isAssignableFrom(authentication);
  }

  private RegisteredClient convert(OidcClientRegistration oidcClientRegistration) {
    RegisteredClient client = registeredClientConverter.convert(oidcClientRegistration);
    if (client == null) {
      throw new IllegalArgumentException("Client is mandatory");
    }
    Builder clientBuilder = RegisteredClient.from(client)
                                            .id(client.getClientId());
    if (StringUtils.isNotBlank(client.getClientSecret())) {
      clientBuilder.clientSecret(passwordEncoder.encode(client.getClientSecret()));
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
    CUSTOM_CLIENT_METADATA.stream()
                          .filter(c -> clientSettings.getSetting(c) != null)
                          .forEach(c -> claims.put(c, clientSettings.getSetting(c)));
    OidcClientRegistration.Builder oidcClientRegistrationBuilder = OidcClientRegistration.withClaims(claims);
    if (StringUtils.isNotBlank(oidcClientRegistration.getClientSecret())) {
      oidcClientRegistrationBuilder.clientSecret(passwordEncoder.decode(client.getClientSecret()));
    }
    return oidcClientRegistrationBuilder.build();
  }

}
