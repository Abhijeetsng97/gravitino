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

package org.apache.gravitino.server.authorization;

import static org.apache.gravitino.authorization.Privilege.Name.SELECT_TABLE;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.apache.gravitino.MetadataObject;
import org.apache.gravitino.MetadataObjects;
import org.apache.gravitino.UserPrincipal;
import org.apache.gravitino.authorization.AuthorizationRequestContext;
import org.apache.gravitino.authorization.GravitinoAuthorizer;
import org.apache.gravitino.authorization.ResolvedTagPolicy;
import org.apache.gravitino.meta.PolicyEntity;
import org.apache.gravitino.meta.TagEntity;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.junit.jupiter.api.Test;

/** Tests RBAC and tag-policy composition, including deny-suppression diagnostics. */
public class TestTagAuthorizationAdapter {
  private final GravitinoAuthorizer authorizer = mock(GravitinoAuthorizer.class);
  private final TagAuthorizationAdapter adapter = new TagAuthorizationAdapter(authorizer);
  private final UserPrincipal principal = new UserPrincipal("alice");
  private final AuthorizationRequestContext context = new AuthorizationRequestContext();
  private final MetadataObject catalog =
      MetadataObjects.parse("catalog", MetadataObject.Type.CATALOG);
  private final MetadataObject table =
      MetadataObjects.parse("catalog.schema.table", MetadataObject.Type.TABLE);

  /** Tests that an RBAC allow without a deny skips tag-policy resolution. */
  @Test
  public void testRbacAllowSkipsTags() {
    when(authorizer.authorize(principal, "metalake", catalog, SELECT_TABLE, context))
        .thenReturn(true);
    assertTrue(evaluate());
    verify(authorizer, never()).matchTagPolicy(any(), any(), any(), any(), any());
  }

  /** Tests that a matching tag policy can satisfy an RBAC miss. */
  @Test
  public void testRbacMissAllowsMatchingTag() {
    doReturn(Optional.of(binding()))
        .when(authorizer)
        .matchTagPolicy(principal, "metalake", table, SELECT_TABLE, context);
    assertTrue(evaluate());
    verify(authorizer).matchTagPolicy(principal, "metalake", table, SELECT_TABLE, context);
    verify(authorizer, never())
        .matchTagPolicy(principal, "metalake", catalog, SELECT_TABLE, context);
  }

  /** Tests denial when neither RBAC nor a tag policy allows the privilege. */
  @Test
  public void testRbacMissAndNoMatchDeny() {
    assertFalse(evaluate());
  }

  /** Tests deny precedence and suppression diagnostics when RBAC also allows access. */
  @Test
  public void testExplicitDenySuppressesAndIdentifiesTagEvenWithRbacAllow() {
    when(authorizer.authorize(principal, "metalake", catalog, SELECT_TABLE, context))
        .thenReturn(true);
    when(authorizer.deny(principal, "metalake", catalog, SELECT_TABLE, context)).thenReturn(true);
    doReturn(Optional.of(binding()))
        .when(authorizer)
        .matchTagPolicy(principal, "metalake", table, SELECT_TABLE, context);
    LoggerContext logging = (LoggerContext) LogManager.getContext(false);
    Configuration configuration = logging.getConfiguration();
    String loggerName = TagAuthorizationAdapter.class.getName();
    LoggerConfig previous = configuration.getLoggers().get(loggerName);
    LoggerConfig capture = new LoggerConfig(loggerName, Level.INFO, false);
    Appender appender = mock(Appender.class);
    when(appender.getName()).thenReturn("tagAccessCapture");
    when(appender.isStarted()).thenReturn(true);
    List<String> messages = new ArrayList<>();
    doAnswer(
            invocation -> {
              messages.add(
                  ((LogEvent) invocation.getArgument(0)).getMessage().getFormattedMessage());
              return null;
            })
        .when(appender)
        .append(any(LogEvent.class));
    capture.addAppender(appender, Level.INFO, null);
    configuration.removeLogger(loggerName);
    configuration.addLogger(loggerName, capture);
    logging.updateLoggers();
    try {
      assertFalse(evaluate());
      assertTrue(
          messages.stream()
              .anyMatch(
                  message ->
                      message.contains("Suppressed tag allow")
                          && message.contains("tag certified (11)")
                          && message.contains("policy read_certified (12)")
                          && message.contains("SELECT_TABLE")
                          && message.contains("catalog.schema.table")
                          && message.contains("deny scope CATALOG:catalog")));
    } finally {
      configuration.removeLogger(loggerName);
      if (previous != null) {
        configuration.addLogger(loggerName, previous);
      }
      logging.updateLoggers();
    }
  }

  /** Tests that an RBAC deny suppresses a tag-only grant. */
  @Test
  public void testExplicitDenySuppressesTagWithoutRbacAllow() {
    when(authorizer.deny(principal, "metalake", table, SELECT_TABLE, context)).thenReturn(true);
    doReturn(Optional.of(binding()))
        .when(authorizer)
        .matchTagPolicy(principal, "metalake", table, SELECT_TABLE, context);
    assertFalse(evaluate());
  }

  /** Tests that a tag-policy read failure propagates instead of becoming a non-match. */
  @Test
  public void testReadFailureRemainsAnError() {
    RuntimeException failure = new IllegalStateException("policy read failed");
    when(authorizer.matchTagPolicy(principal, "metalake", table, SELECT_TABLE, context))
        .thenThrow(failure);
    assertSame(failure, assertThrows(IllegalStateException.class, this::evaluate));
  }

  /** Tests that a missing target cannot inherit a grant from an ancestor check. */
  @Test
  public void testMissingTargetDoesNotEvaluateAncestorTags() {
    assertFalse(
        adapter.authorize(
            principal, "metalake", Arrays.asList(catalog, null), SELECT_TABLE, context));
    verify(authorizer, never()).matchTagPolicy(any(), any(), any(), any(), any());
  }

  private boolean evaluate() {
    return adapter.authorize(principal, "metalake", List.of(catalog, table), SELECT_TABLE, context);
  }

  private ResolvedTagPolicy binding() {
    TagEntity tag = mock(TagEntity.class);
    when(tag.name()).thenReturn("certified");
    when(tag.id()).thenReturn(11L);
    PolicyEntity policy = mock(PolicyEntity.class);
    when(policy.name()).thenReturn("read_certified");
    when(policy.id()).thenReturn(12L);
    ResolvedTagPolicy binding = mock(ResolvedTagPolicy.class);
    when(binding.tag()).thenReturn(tag);
    when(binding.policy()).thenReturn(policy);
    return binding;
  }
}
