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
package io.meeds.oauth2.server.plugin;

import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_IS_CIMD_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_LOGO_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_POLICY_URI_SETTING;
import static io.meeds.oauth2.server.util.EntityMapper.CLIENT_URI_SETTING;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings.Builder;
import org.springframework.stereotype.Component;

import io.meeds.oauth2.server.model.OAuthCimdClientMetadata;
import io.meeds.oauth2.server.service.OAuthSettingService;

@Component
public class OAuthCimdClientConverter {

  @Autowired
  private OAuthSettingService oAuthSettingService;

  public RegisteredClient convert(OAuthCimdClientMetadata metadata, Set<String> scopes) {
    Builder clientSettingsBuilder = ClientSettings.builder()
                                                  .setting(CLIENT_IS_CIMD_SETTING, true)
                                                  .requireProofKey(true)
                                                  .requireAuthorizationConsent(true);
    if (StringUtils.isNotBlank(metadata.jwksUri())) {
      clientSettingsBuilder.jwkSetUrl(metadata.jwksUri());
    }
    if (StringUtils.isNotBlank(metadata.tokenEndpointAuthSigningAlg())) {
      clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.from(metadata.tokenEndpointAuthSigningAlg()));
    }
    if (StringUtils.isNotBlank(metadata.clientUri())) {
      clientSettingsBuilder.setting(CLIENT_URI_SETTING, metadata.clientUri());
    }
    if (StringUtils.isNotBlank(metadata.logoUri())) {
      clientSettingsBuilder.setting(CLIENT_LOGO_URI_SETTING, metadata.logoUri());
    }
    if (StringUtils.isNotBlank(metadata.policyUri())) {
      clientSettingsBuilder.setting(CLIENT_POLICY_URI_SETTING, metadata.policyUri());
    }
    Set<String> metadataScopes = scopes == null ? new HashSet<>() : new HashSet<>(scopes);
    if (StringUtils.isNotBlank(metadata.scope())) {
      Collections.addAll(metadataScopes, metadata.scope().trim().split("\\s+"));
    }
    List<String> metadataGrantTypes = metadata.grantTypes();

    ClientSettings clientSettings = clientSettingsBuilder.build();
    return RegisteredClient.withId(metadata.clientId())
                           .clientName(metadata.clientName())
                           .clientId(metadata.clientId())
                           .clientSettings(clientSettings)
                           .clientAuthenticationMethod(ClientAuthenticationMethod.valueOf(metadata.tokenEndpointAuthMethod()))
                           .authorizationGrantTypes(a -> a.addAll(metadataGrantTypes.stream()
                                                                                    .map(AuthorizationGrantType::new)
                                                                                    .toList()))
                           .redirectUris(r -> r.addAll(metadata.redirectUris()))
                           .scopes(s -> metadataScopes.stream()
                                                      .filter(oAuthSettingService.getScopes()::contains)
                                                      .forEach(s::add))
                           .build();
  }

}
