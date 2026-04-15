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

import java.net.URI;
import java.util.TimeZone;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.introspect.VisibilityChecker;
import com.fasterxml.jackson.databind.util.StdDateFormat;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import io.meeds.oauth2.server.model.OAuthCimdClientMetadata;
import io.meeds.oauth2.server.util.Utils;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class OAuthCimdClientResolver {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  static {
    OBJECT_MAPPER.findAndRegisterModules();
    OBJECT_MAPPER.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    OBJECT_MAPPER.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    OBJECT_MAPPER.setVisibility(VisibilityChecker.Std.defaultInstance().withFieldVisibility(JsonAutoDetect.Visibility.ANY));
    OBJECT_MAPPER.registerModule(new JavaTimeModule());
    OBJECT_MAPPER.setDateFormat(new StdDateFormat().withTimeZone(TimeZone.getTimeZone("UTC")));
  }

  @Autowired
  private RestClient restClient;

  @Value("${meeds.oauth.cimd.enabled:true}")
  private boolean    enabled;

  @SneakyThrows
  public OAuthCimdClientMetadata resolve(String clientId) {
    URI clientIdUri = Utils.validateUrl(clientId);
    String body;
    try {
      body = this.restClient.get()
                            .uri(clientIdUri)
                            .accept(MediaType.APPLICATION_JSON)
                            .retrieve()
                            .onStatus(HttpStatusCode::isError, (request, response) -> {
                              throw new IllegalArgumentException("CIMD fetch failed with HTTP " + response.getStatusCode());
                            })
                            .body(String.class);
    } catch (RestClientResponseException e) {
      throw new IllegalStateException("CIMD fetch for '%s' failed: %s. Body: %s".formatted(clientIdUri,
                                                                                           e.getStatusCode(),
                                                                                           e.getResponseBodyAsString()),
                                      e);
    } catch (Exception e) {
      throw new IllegalStateException("CIMD fetch for '%s' failed".formatted(clientIdUri),
                                      e);
    }
    try {
      OAuthCimdClientMetadata metadata = OBJECT_MAPPER.readValue(body, OAuthCimdClientMetadata.class);
      if (metadata.clientId() == null || !metadata.clientId().equals(clientId)) {
        throw new IllegalStateException("metadata.client_id must exactly match the client_id URL");
      } else if (CollectionUtils.isEmpty(metadata.redirectUris())) {
        throw new IllegalArgumentException("redirect_uris must not be empty");
      } else if (StringUtils.isBlank(metadata.tokenEndpointAuthMethod())) {
        throw new IllegalStateException("token_endpoint_auth_method is required");
      } else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(metadata.tokenEndpointAuthMethod())
                 && StringUtils.isBlank(metadata.jwksUri())) {
        throw new IllegalStateException("jwks_uri is required for 'private_key_jwt' token_endpoint_auth_method");
      } else if (ClientAuthenticationMethod.NONE.getValue().equals(metadata.tokenEndpointAuthMethod())
                 && StringUtils.isNotBlank(metadata.jwksUri())) {
        throw new IllegalStateException("jwks_uri must be empty for 'none' token_endpoint_auth_method");
      }
      return metadata;
    } catch (IllegalStateException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException("Invalid CIMD JSON document: %s".formatted(body), e);
    }
  }

}
