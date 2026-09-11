/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.gravitino.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.apache.gravitino.NameIdentifier;
import org.apache.gravitino.Version;
import org.apache.gravitino.dto.AuditDTO;
import org.apache.gravitino.dto.MetalakeDTO;
import org.apache.gravitino.dto.VersionDTO;
import org.apache.gravitino.dto.responses.EntityListResponse;
import org.apache.gravitino.dto.responses.ErrorResponse;
import org.apache.gravitino.dto.responses.MetalakeResponse;
import org.apache.gravitino.dto.responses.VersionResponse;
import org.apache.gravitino.exceptions.GravitinoRuntimeException;
import org.apache.gravitino.exceptions.NoSuchMetalakeException;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.Method;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.mockserver.model.HttpRequest;
import org.mockserver.verify.VerificationTimes;

/** Tests lazy initialization of the metalake-scoped client. */
public class TestGravitinoClient extends TestBase {

  private static final String METALAKE = "test";
  private static final String METALAKE_PATH = "/api/metalakes/" + METALAKE;
  private static final String CATALOGS_PATH = METALAKE_PATH + "/catalogs";

  /** Clears requests and expectations between tests. */
  @BeforeEach
  public void resetServer() {
    mockServer.reset();
  }

  /** Construction defers remote calls and authentication until the first operation. */
  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  public void testLazyInitialization(boolean checkVersion) throws JsonProcessingException {
    CustomTokenProvider authDataProvider = Mockito.mock(CustomTokenProvider.class);
    GravitinoClient.ClientBuilder builder = newBuilder();
    builder.withCustomTokenAuth(authDataProvider);
    if (!checkVersion) {
      builder.withVersionCheckDisabled();
    }

    try (GravitinoClient gravitinoClient = builder.build()) {
      mockServer.verify(HttpRequest.request(), VerificationTimes.exactly(0));
      Mockito.verifyNoInteractions(authDataProvider);

      Mockito.when(authDataProvider.getTokenData())
          .thenReturn("Bearer first-caller".getBytes(StandardCharsets.UTF_8));
      if (checkVersion) {
        buildMockResource(
            Method.GET,
            "/api/version",
            null,
            new VersionResponse(Version.getCurrentVersionDTO()),
            HttpStatus.SC_OK);
      }
      mockMetalake();
      mockCatalogs();
      Assertions.assertArrayEquals(new String[] {"catalog"}, gravitinoClient.listCatalogs());

      Mockito.when(authDataProvider.getTokenData())
          .thenReturn("Bearer second-caller".getBytes(StandardCharsets.UTF_8));
      mockCatalogs();
      Assertions.assertArrayEquals(new String[] {"catalog"}, gravitinoClient.listCatalogs());

      mockServer.verify(
          HttpRequest.request(METALAKE_PATH)
              .withHeader(HttpHeaders.AUTHORIZATION, "Bearer first-caller"),
          VerificationTimes.once());
      mockServer.verify(
          HttpRequest.request("/api/version"), VerificationTimes.exactly(checkVersion ? 1 : 0));
      mockServer.verify(
          HttpRequest.request(CATALOGS_PATH)
              .withHeader(HttpHeaders.AUTHORIZATION, "Bearer first-caller"),
          VerificationTimes.once());
      mockServer.verify(
          HttpRequest.request(CATALOGS_PATH)
              .withHeader(HttpHeaders.AUTHORIZATION, "Bearer second-caller"),
          VerificationTimes.once());
    }
  }

  /** Missing metalakes fail on use, and a failed load can be retried with the same client. */
  @Test
  public void testMissingMetalakeOnFirstUse() throws JsonProcessingException {
    buildMockResource(
        Method.GET,
        METALAKE_PATH,
        null,
        ErrorResponse.notFound(NoSuchMetalakeException.class.getSimpleName(), "metalake missing"),
        HttpStatus.SC_NOT_FOUND);

    try (GravitinoClient gravitinoClient = newBuilder().withVersionCheckDisabled().build()) {
      mockServer.verify(HttpRequest.request(), VerificationTimes.exactly(0));
      NoSuchMetalakeException exception =
          Assertions.assertThrows(NoSuchMetalakeException.class, gravitinoClient::listCatalogs);
      Assertions.assertTrue(exception.getMessage().contains("metalake missing"));
      mockServer.verify(HttpRequest.request(CATALOGS_PATH), VerificationTimes.exactly(0));

      mockMetalake();
      mockCatalogs();
      Assertions.assertArrayEquals(new String[] {"catalog"}, gravitinoClient.listCatalogs());
      mockServer.verify(HttpRequest.request(METALAKE_PATH), VerificationTimes.exactly(2));
    }
  }

  /** Version incompatibility is reported on use and checked before loading the metalake. */
  @Test
  public void testVersionCheckOnFirstUse() throws JsonProcessingException {
    buildMockResource(
        Method.GET,
        "/api/version",
        null,
        new VersionResponse(new VersionDTO("0.1.1", "2024-01-03 12:28:33", "6ef1f9d")),
        HttpStatus.SC_OK);

    try (GravitinoClient gravitinoClient = newBuilder().build()) {
      mockServer.verify(HttpRequest.request(), VerificationTimes.exactly(0));
      Assertions.assertThrows(GravitinoRuntimeException.class, gravitinoClient::listCatalogs);
      mockServer.verify(HttpRequest.request("/api/version"), VerificationTimes.once());
      mockServer.verify(HttpRequest.request(METALAKE_PATH), VerificationTimes.exactly(0));
      mockServer.verify(HttpRequest.request(CATALOGS_PATH), VerificationTimes.exactly(0));
    }
  }

  /** Invalid names are still rejected during construction without contacting the server. */
  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"parent.metalake", "metalake."})
  public void testInvalidMetalakeName(String metalakeName) {
    Assertions.assertThrows(
        IllegalArgumentException.class, () -> newBuilder().withMetalake(metalakeName).build());
    mockServer.verify(HttpRequest.request(), VerificationTimes.exactly(0));
  }

  private GravitinoClient.ClientBuilder newBuilder() {
    return GravitinoClient.builder("http://127.0.0.1:" + mockServer.getLocalPort())
        .withMetalake(METALAKE);
  }

  private void mockMetalake() throws JsonProcessingException {
    MetalakeDTO metalake =
        MetalakeDTO.builder()
            .withName(METALAKE)
            .withAudit(
                AuditDTO.builder().withCreator("creator").withCreateTime(Instant.now()).build())
            .build();
    buildMockResource(
        Method.GET, METALAKE_PATH, null, new MetalakeResponse(metalake), HttpStatus.SC_OK);
  }

  private void mockCatalogs() throws JsonProcessingException {
    buildMockResource(
        Method.GET,
        CATALOGS_PATH,
        null,
        new EntityListResponse(new NameIdentifier[] {NameIdentifier.of(METALAKE, "catalog")}),
        HttpStatus.SC_OK);
  }
}
