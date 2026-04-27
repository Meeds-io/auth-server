package io.meeds.oauth2.server.model;

import java.time.Instant;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuthJwkSet {

  private List<OAuthJwkEntry> entries;

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OAuthJwkEntry {

    private String  keyPairJson;

    private Instant activatedAt;

  }

}
