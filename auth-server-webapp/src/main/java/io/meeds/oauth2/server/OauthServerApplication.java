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
package io.meeds.oauth2.server;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.ApplicationContextFactory;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;

import org.exoplatform.container.ExoContainer;

import io.meeds.spring.AvailableIntegration;
import io.meeds.spring.kernel.PortalApplicationContext;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;

@SpringBootApplication(scanBasePackages = {
  OauthServerApplication.MODULE_NAME,
  OauthServerApplication.SPRING_OAUTH2_SERVER,
  AvailableIntegration.JPA_MODULE,
  AvailableIntegration.WEB_MODULE,
  AvailableIntegration.LIQUIBASE_MODULE,
  AvailableIntegration.KERNEL_MODULE,
}, exclude = {
  OAuth2AuthorizationServerAutoConfiguration.class,
})
@EnableJpaRepositories(basePackages = OauthServerApplication.MODULE_NAME)
@EnableScheduling
@PropertySource({
  "classpath:application.properties",
  "classpath:application-common.properties",
  "classpath:auth-server.properties"
})
public class OauthServerApplication extends SpringBootServletInitializer {

  static final String                MODULE_NAME          = "io.meeds.oauth2.server";

  static final String                SPRING_OAUTH2_SERVER = "org.springframework.security.oauth2.server";

  private DefaultListableBeanFactory beanFactory;

  private ServletContext             servletContext;

  @Override
  public void onStartup(ServletContext servletContext) throws ServletException {
    // Used to disable LogBack initialization in WebApp context after having
    // initialized it already in Meeds Server globally
    System.setProperty("org.springframework.boot.logging.LoggingSystem", "none");

    this.servletContext = servletContext;
    this.servletContext.setInitParameter("spring.profiles.active", StringUtils.join(ExoContainer.getProfiles(), ","));
    // Force ignore Builtin SecurityFilterChain for OAuth2 to use customized one
    this.beanFactory = new DefaultListableBeanFactory() {
      @Override
      public void registerBeanDefinition(String beanName, BeanDefinition beanDefinition) throws BeanDefinitionStoreException {
        if (!"OAuth2AuthorizationServerConfiguration".equals(beanDefinition.getFactoryBeanName())
            || !"authorizationServerSecurityFilterChain".equals(beanName)) {
          super.registerBeanDefinition(beanName, beanDefinition);
        }
      }
    };
    super.onStartup(servletContext);
  }

  @Override
  protected SpringApplicationBuilder createSpringApplicationBuilder() {
    return new SpringApplicationBuilder() {
      @Override
      public SpringApplicationBuilder contextFactory(ApplicationContextFactory factory) {
        return super.contextFactory(w -> new PortalApplicationContext(servletContext, beanFactory, false));
      }
    };
  }

}
