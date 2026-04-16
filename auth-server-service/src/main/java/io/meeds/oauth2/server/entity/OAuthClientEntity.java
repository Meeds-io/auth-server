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
package io.meeds.oauth2.server.entity;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import io.meeds.oauth2.server.model.OauthClientType;
import io.meeds.oauth2.server.util.JsonMapConverter;
import io.meeds.oauth2.server.util.JsonSetConverter;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity(name = "OAuthClient")
@Table(name = "AUTH_SERVER_CLIENTS")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuthClientEntity {

  @Id
  @SequenceGenerator(name = "SEQ_AUTH_SERVER_CLIENTS_ID", sequenceName = "SEQ_AUTH_SERVER_CLIENTS_ID", allocationSize = 1)
  @GeneratedValue(strategy = GenerationType.AUTO, generator = "SEQ_AUTH_SERVER_CLIENTS_ID")
  @Column(name = "ID")
  private Long                id;

  @Column(name = "REGISTERED_CLIENT_ID")
  private String              registeredClientId;

  @Column(name = "CLIENT_ID")
  private String              clientId;

  @Column(name = "CLIENT_NAME")
  private String              clientName;

  @Column(name = "CLIENT_SECRET")
  private String              clientSecret;

  @Column(name = "CLIENT_TYPE")
  @Enumerated(EnumType.STRING)
  private OauthClientType     clientType;

  @Column(name = "CLIENT_ISSUED_AT")
  private Instant             clientIssuedAt;

  @Column(name = "CLIENT_AUTH_METHOD")
  @Convert(converter = JsonSetConverter.class)
  private Set<String>         clientAuthenticationMethods;

  @Column(name = "GRANT_TYPES")
  @Convert(converter = JsonSetConverter.class)
  private Set<String>         grantTypes;

  @Column(name = "SCOPES")
  @Convert(converter = JsonSetConverter.class)
  private Set<String>         scopes;

  @Column(name = "ICON_URL")
  private String              iconUrl;

  @Column(name = "ENABLED")
  private boolean             enabled;

  @Column(name = "REDIRECT_URI")
  @Convert(converter = JsonSetConverter.class)
  private Set<String>         redirectUris;

  @Column(name = "CLIENT_SETTINGS")
  @Convert(converter = JsonMapConverter.class)
  private Map<String, Object> clientSettings;

  @Column(name = "TOKEN_SETTINGS")
  @Convert(converter = JsonMapConverter.class)
  private Map<String, Object> tokenSettings;

  @CreatedDate
  @Column(name = "CREATED_DATE")
  private Instant             createdDate;

  @LastModifiedDate
  @Column(name = "MODIFIED_DATE")
  private Instant             modifiedDate;

  @PrePersist
  void onCreate() {
    Instant now = Instant.now();
    this.createdDate = now;
    this.modifiedDate = now;
  }

  @PreUpdate
  void onUpdate() {
    this.modifiedDate = Instant.now();
  }

}
