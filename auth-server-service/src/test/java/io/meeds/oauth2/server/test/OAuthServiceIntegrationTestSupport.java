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
package io.meeds.oauth2.server.test;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import io.meeds.kernel.test.AbstractSpringTest;
import io.meeds.kernel.test.KernelExtension;

@SpringBootTest(classes = IntegrationTestBaseTestApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@ExtendWith({ SpringExtension.class, KernelExtension.class })
public abstract class OAuthServiceIntegrationTestSupport extends AbstractSpringTest {

  @BeforeEach
  public void beginRequest() {
    getContainer();
    begin();
    setUp();
  }

  @AfterEach
  public void endRequest() {
    tearDown();
    end();
  }

  protected void setUp() {
  }

  protected void tearDown() {
  }

}
