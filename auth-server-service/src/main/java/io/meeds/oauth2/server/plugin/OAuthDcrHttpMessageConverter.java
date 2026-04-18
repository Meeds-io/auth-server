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

import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.meeds.oauth2.server.service.OAuthSettingService;

/**
 * Override default in order to allow using DCR with empty scopes
 */
@Component
public class OAuthDcrHttpMessageConverter extends OidcClientRegistrationHttpMessageConverter {

  public OAuthDcrHttpMessageConverter(OAuthSettingService oAuthSettingService) {
    setClientRegistrationConverter(new OAuthDcrConverter(oAuthSettingService));
  }

  private static final class OAuthDcrConverter implements Converter<Map<String, Object>, OidcClientRegistration> {

    private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService.getSharedInstance();

    private static final TypeDescriptor         OBJECT_TYPE_DESCRIPTOR   = TypeDescriptor.valueOf(Object.class);

    private static final TypeDescriptor         STRING_TYPE_DESCRIPTOR   = TypeDescriptor.valueOf(String.class);

    private static final TypeDescriptor         INSTANT_TYPE_DESCRIPTOR  = TypeDescriptor.valueOf(Instant.class);

    private static final TypeDescriptor         URL_TYPE_DESCRIPTOR      = TypeDescriptor.valueOf(URL.class);

    private static final Converter<Object, ?>   INSTANT_CONVERTER        = getConverter(INSTANT_TYPE_DESCRIPTOR);

    private ClaimTypeConverter                  claimTypeConverter;

    private OAuthSettingService                 oAuthSettingService;

    private OAuthDcrConverter(OAuthSettingService oAuthSettingService) {
      this.oAuthSettingService = oAuthSettingService;
      Converter<Object, ?> stringConverter = getConverter(STRING_TYPE_DESCRIPTOR);
      Converter<Object, ?> collectionStringConverter = getConverter(
                                                                    TypeDescriptor.collection(Collection.class,
                                                                                              STRING_TYPE_DESCRIPTOR));
      Converter<Object, ?> urlConverter = getConverter(URL_TYPE_DESCRIPTOR);

      Map<String, Converter<Object, ?>> claimConverters = new HashMap<>();
      claimConverters.put(OidcClientMetadataClaimNames.CLIENT_ID, stringConverter);
      claimConverters.put(OidcClientMetadataClaimNames.CLIENT_ID_ISSUED_AT, INSTANT_CONVERTER);
      claimConverters.put(OidcClientMetadataClaimNames.CLIENT_SECRET, stringConverter);
      claimConverters.put(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT, this::convertClientSecretExpiresAt);
      claimConverters.put(OidcClientMetadataClaimNames.CLIENT_NAME, stringConverter);
      claimConverters.put(OidcClientMetadataClaimNames.REDIRECT_URIS, collectionStringConverter);
      claimConverters.put(OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS, collectionStringConverter);
      claimConverters.put(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD, stringConverter);
      claimConverters.put(OidcClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_SIGNING_ALG, stringConverter);
      claimConverters.put(OidcClientMetadataClaimNames.GRANT_TYPES, collectionStringConverter);
      claimConverters.put(OidcClientMetadataClaimNames.RESPONSE_TYPES, collectionStringConverter);
      claimConverters.put(OidcClientMetadataClaimNames.SCOPE, this::convertScope);
      claimConverters.put(OidcClientMetadataClaimNames.JWKS_URI, urlConverter);
      claimConverters.put(OidcClientMetadataClaimNames.ID_TOKEN_SIGNED_RESPONSE_ALG, stringConverter);
      this.claimTypeConverter = new ClaimTypeConverter(claimConverters);
    }

    @Override
    public OidcClientRegistration convert(Map<String, Object> source) {
      Map<String, Object> parsedClaims = this.claimTypeConverter.convert(source);
      if (!parsedClaims.containsKey(OidcClientMetadataClaimNames.SCOPE)) { // NOSONAR
        parsedClaims.put(OidcClientMetadataClaimNames.SCOPE, convertScope(null));
      }
      Object clientSecretExpiresAt = parsedClaims.get(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT); // NOSONAR
      if (clientSecretExpiresAt instanceof Number && clientSecretExpiresAt.equals(0)) {
        parsedClaims.remove(OidcClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT);
      }
      return OidcClientRegistration.withClaims(parsedClaims).build();
    }

    private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
      return source -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
    }

    private Instant convertClientSecretExpiresAt(Object clientSecretExpiresAt) {
      if (clientSecretExpiresAt == null || String.valueOf(clientSecretExpiresAt).equals("0")) {
        // 0 indicates that client_secret_expires_at does not expire
        return null;
      } else {
        return (Instant) INSTANT_CONVERTER.convert(clientSecretExpiresAt);
      }
    }

    private List<String> convertScope(Object scope) {
      if (scope == null || !StringUtils.hasText(scope.toString())) {
        return new ArrayList<>(oAuthSettingService.getScopes());
      } else {
        return Arrays.asList(StringUtils.delimitedListToStringArray(scope.toString(), " "));
      }
    }

  }

}
