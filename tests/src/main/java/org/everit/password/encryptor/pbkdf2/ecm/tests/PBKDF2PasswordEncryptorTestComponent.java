/*
 * Copyright (C) 2011 Everit Kft. (http://www.everit.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.everit.password.encryptor.pbkdf2.ecm.tests;

import java.util.UUID;

import org.everit.credential.encryptor.CredentialEncryptor;
import org.everit.credential.encryptor.CredentialMatcher;
import org.everit.osgi.dev.testrunner.TestRunnerConstants;
import org.everit.osgi.ecm.annotation.Component;
import org.everit.osgi.ecm.annotation.ConfigurationPolicy;
import org.everit.osgi.ecm.annotation.Service;
import org.everit.osgi.ecm.annotation.ServiceRef;
import org.everit.osgi.ecm.annotation.attribute.StringAttribute;
import org.everit.osgi.ecm.annotation.attribute.StringAttributes;
import org.everit.osgi.ecm.extender.ExtendComponent;
import org.junit.Assert;
import org.junit.Test;
import org.osgi.service.log.LogService;

/**
 * Test for PBKDF2PasswordEncryptor component.
 */
@ExtendComponent
@Component(componentId = "PBKDF2PasswordEncryptorTest",
    configurationPolicy = ConfigurationPolicy.OPTIONAL)
@StringAttributes({
    @StringAttribute(attributeId = TestRunnerConstants.SERVICE_PROPERTY_TESTRUNNER_ENGINE_TYPE,
        defaultValue = "junit4"),
    @StringAttribute(attributeId = TestRunnerConstants.SERVICE_PROPERTY_TEST_ID,
        defaultValue = "PBKDF2PasswordEncryptorTest") })
@Service(value = PBKDF2PasswordEncryptorTestComponent.class)
public class PBKDF2PasswordEncryptorTestComponent {

  private static final int COUNT_1000 = 1000;

  private CredentialEncryptor credentialEncryptor;

  private CredentialMatcher credentialMatcher;

  private LogService logService;

  @ServiceRef(defaultValue = "")
  public void setCredentialEncryptor(final CredentialEncryptor credentialEncryptor) {
    this.credentialEncryptor = credentialEncryptor;
  }

  @ServiceRef(defaultValue = "")
  public void setCredentialMatcher(final CredentialMatcher credentialMatcher) {
    this.credentialMatcher = credentialMatcher;
  }

  @ServiceRef(defaultValue = "")
  public void setLogService(final LogService logService) {
    this.logService = logService;
  }

  @Test
  public void testArgumentValidations() {
    try {
      credentialEncryptor.encrypt(null);
      Assert.fail();
    } catch (NullPointerException e) {
      Assert.assertEquals("plainPassword cannot be null", e.getMessage());
    }
    Assert.assertFalse(credentialMatcher.match(null, null));
    Assert.assertFalse(credentialMatcher.match("", null));
  }

  @Test
  public void testCredentialEncryptionAndValidation() {
    String encryptedCredential = credentialEncryptor.encrypt("foo");
    Assert.assertNotNull(encryptedCredential);
    Assert.assertTrue(credentialMatcher.match("foo", encryptedCredential));
    Assert.assertFalse(credentialMatcher.match("bar", encryptedCredential));
  }

  @Test
  public void testPerformance() {
    String[] plainCredentials = new String[COUNT_1000];
    for (int i = 0; i < COUNT_1000; i++) {
      plainCredentials[i] = UUID.randomUUID().toString();
    }
    String[] encryptedCredentials = new String[COUNT_1000];

    long startAt = System.currentTimeMillis();
    for (int i = 0; i < COUNT_1000; i++) {
      encryptedCredentials[i] = credentialEncryptor.encrypt(plainCredentials[i]);
      Assert.assertNotNull(encryptedCredentials[i]);
    }
    long encryptnDuration = System.currentTimeMillis() - startAt;

    startAt = System.currentTimeMillis();
    for (int i = 0; i < COUNT_1000; i++) {
      Assert.assertTrue(credentialMatcher.match(plainCredentials[i], encryptedCredentials[i]));
    }
    long matchDuration = System.currentTimeMillis() - startAt;

    logService.log(LogService.LOG_INFO,
        "Encrypting " + COUNT_1000 + " credentials take " + encryptnDuration + " ms");
    logService.log(LogService.LOG_INFO,
        "Matching " + COUNT_1000 + " credentials take " + matchDuration + " ms");
  }

}
