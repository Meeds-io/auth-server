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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TimeZone;
import java.util.stream.Collectors;

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
import lombok.extern.slf4j.Slf4j;

@Converter
@Slf4j
public class JsonMapConverter implements AttributeConverter<Map<String, Object>, String> {

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

  @SuppressWarnings({ "rawtypes", "unchecked" })
  @Override
  public String convertToDatabaseColumn(Map<String, Object> map) {
    try {
      if (map == null) {
        return null;
      } else {
        map = map.entrySet()
                 .stream()
                 .map(e -> {
                   if (e.getValue() instanceof List list) {
                     return Map.entry(e.getKey(), new ArrayList(list));
                   } else if (e.getValue() instanceof Set set) {
                     return Map.entry(e.getKey(), new HashSet(set));
                   } else if (e.getValue() instanceof Map m) {
                     return Map.entry(e.getKey(), new LinkedHashMap(m));
                   } else {
                     return e;
                   }
                 })
                 .collect(Collectors.toMap(Entry::getKey, Entry::getValue));
        return OBJECT_MAPPER.writeValueAsString(new LinkedHashMap<>(map));
      }
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException("Failed to serialize JSON column", e);
    }
  }

  @Override
  public Map<String, Object> convertToEntityAttribute(String value) { // NOSONAR
    if (StringUtils.isBlank(value)) {
      return new HashMap<>();
    } else {
      try {
        return OBJECT_MAPPER.readValue(value, new TypeReference<>() {
        });
      } catch (Exception e) {
        throw new IllegalArgumentException("Failed to deserialize JSON map column", e);
      }
    }
  }

}
