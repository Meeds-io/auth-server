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
package io.meeds.oauth2.server.util;

import java.util.HashSet;
import java.util.Set;
import java.util.TimeZone;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.jaas.JaasGrantedAuthority;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.web.jackson2.WebJackson2Module;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.introspect.VisibilityChecker;
import com.fasterxml.jackson.databind.util.StdDateFormat;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import org.exoplatform.services.security.jaas.UserPrincipal;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class JsonSetConverter implements AttributeConverter<Set<String>, String> {

  public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  static {
    OBJECT_MAPPER.findAndRegisterModules();
    OBJECT_MAPPER.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    OBJECT_MAPPER.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    OBJECT_MAPPER.setVisibility(VisibilityChecker.Std.defaultInstance().withFieldVisibility(JsonAutoDetect.Visibility.ANY));
    OBJECT_MAPPER.registerModule(new JavaTimeModule());
    OBJECT_MAPPER.setDateFormat(new StdDateFormat().withTimeZone(TimeZone.getTimeZone("UTC")));
    ClassLoader cl = JsonMapConverter.class.getClassLoader();
    OBJECT_MAPPER.registerModules(SecurityJackson2Modules.getModules(cl));
    OBJECT_MAPPER.registerModule(new OAuth2AuthorizationServerJackson2Module());
    OBJECT_MAPPER.registerModule(new WebJackson2Module());
    OBJECT_MAPPER.addMixIn(UserPrincipal.class, UserPrincipalMixin.class);
    OBJECT_MAPPER.addMixIn(JaasGrantedAuthority.class, JaasGrantedAuthorityMixin.class);
  }

  @Override
  public String convertToDatabaseColumn(Set<String> set) {
    try {
      return set == null ? null : OBJECT_MAPPER.writeValueAsString(set);
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException("Failed to serialize JSON column", e);
    }
  }

  @Override
  public Set<String> convertToEntityAttribute(String value) {
    if (StringUtils.isBlank(value)) {
      return new HashSet<>();
    } else {
      try {
        return OBJECT_MAPPER.readValue(value, new TypeReference<>() {
        });
      } catch (Exception e) {
        throw new IllegalArgumentException("Failed to deserialize JSON set column", e);
      }
    }
  }
}
