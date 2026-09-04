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
import java.util.Set;

import org.springframework.data.annotation.CreatedDate;

import io.meeds.oauth2.server.util.JsonSetConverter;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import io.meeds.common.persistence.PortableSequence;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity(name = "OAuthConsent")
@Table(name = "AUTH_SERVER_AUTHORIZATION_CONSENT")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuthConsentEntity {

  @Id
  @PortableSequence(name = "SEQ_AUTH_SERVER_AUTHORIZATION_CONSENTS_ID")
  @Column(name = "ID")
  private Long        id;

  @Column(name = "REGISTERED_CLIENT_ID", nullable = false, length = 100)
  private String      registeredClientId;

  @Column(name = "PRINCIPAL_NAME", nullable = false, length = 200)
  private String      principalName;

  @Column(name = "AUTHORITIES", nullable = false)
  @Convert(converter = JsonSetConverter.class)
  private Set<String> authorities;

  @CreatedDate
  @Column(name = "CREATED_DATE")
  private Instant     createdDate;

  @PrePersist
  void onCreate() {
    this.createdDate = Instant.now();
  }

}
