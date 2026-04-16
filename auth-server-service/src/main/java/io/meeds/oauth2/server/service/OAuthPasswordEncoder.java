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
package io.meeds.oauth2.server.service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import org.exoplatform.web.security.codec.CodecInitializer;
import org.exoplatform.web.security.security.SecureRandomService;
import org.exoplatform.web.security.security.TokenServiceInitializationException;

import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Service("passwordEncoder")
@Slf4j
public class OAuthPasswordEncoder implements PasswordEncoder {

  private static final String UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  private static final String LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";

  private static final String DIGIT_CHARS     = "0123456789";

  private static final String SPECIAL_CHARS   = "!@#$%&*?";

  @Autowired
  private SecureRandomService secureRandomService;

  @Autowired
  private CodecInitializer    codecInitializer;

  @Value("${meeds.oauth.password-encoder.salt.length:20}")
  @Getter
  @Setter
  private int                 saltLength;

  private SecureRandom        secureRandom;

  @Override
  @SneakyThrows
  public String encode(CharSequence rawPassword) {
    if (StringUtils.isBlank(rawPassword)) {
      throw new IllegalArgumentException("password is mandatory");
    }
    String salt = generateSalt();
    return codecInitializer.getCodec().encode(rawPassword + salt);
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    if (StringUtils.isBlank(rawPassword)) {
      throw new IllegalArgumentException("Password is mandatory");
    }
    if (StringUtils.isBlank(encodedPassword)) {
      throw new IllegalArgumentException("Encoded password is mandatory");
    }
    try {
      String password = codecInitializer.getCodec().decode(encodedPassword);
      password = password.substring(0, password.length() - saltLength);
      // Password may be decoded using URLDecoder when read from HTTP Request
      return URLDecoder.decode(password, StandardCharsets.UTF_8)
                       .equals(URLDecoder.decode(String.valueOf(rawPassword), StandardCharsets.UTF_8));
    } catch (Exception e) {
      log.warn("Error while decoding provided password", e);
      return false;
    }
  }

  public String decode(String encodedPassword) {
    if (StringUtils.isBlank(encodedPassword)) {
      throw new IllegalArgumentException("password is mandatory");
    }
    try {
      String password = codecInitializer.getCodec().decode(encodedPassword);
      return password.substring(0, password.length() - saltLength);
    } catch (TokenServiceInitializationException e) {
      throw new IllegalStateException("Error while decoding Encoded Password", e);
    }
  }

  private String generateSalt() {
    List<Character> charPool = new ArrayList<>();
    String allChars = UPPERCASE_CHARS + LOWERCASE_CHARS + DIGIT_CHARS + SPECIAL_CHARS;
    SecureRandom random = getSecureRandom();
    for (int i = 0; i < saltLength - 4; i++) {
      charPool.add(getRandomChar(allChars, random));
    }
    charPool.add(getRandomChar(UPPERCASE_CHARS, random));
    charPool.add(getRandomChar(LOWERCASE_CHARS, random));
    charPool.add(getRandomChar(DIGIT_CHARS, random));
    charPool.add(getRandomChar(SPECIAL_CHARS, random));
    Collections.shuffle(charPool, random);
    StringBuilder finalPassword = new StringBuilder();
    charPool.forEach(finalPassword::append);
    return finalPassword.toString();
  }

  private char getRandomChar(String charSet, SecureRandom random) {
    int index = random.nextInt(charSet.length());
    return charSet.charAt(index);
  }

  private SecureRandom getSecureRandom() {
    if (secureRandom == null) {
      secureRandom = secureRandomService.getSecureRandom();
    }
    return secureRandom;
  }

}
