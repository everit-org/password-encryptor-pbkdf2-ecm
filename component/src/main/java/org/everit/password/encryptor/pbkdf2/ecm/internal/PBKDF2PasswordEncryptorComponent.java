/*
 * Copyright (C) 2011 Everit Kft. (http://www.everit.biz)
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
package org.everit.password.encryptor.pbkdf2.ecm.internal;

import java.util.Dictionary;
import java.util.Hashtable;

import org.everit.credential.encryptor.CredentialEncryptor;
import org.everit.credential.encryptor.CredentialMatcher;
import org.everit.osgi.ecm.annotation.Activate;
import org.everit.osgi.ecm.annotation.Component;
import org.everit.osgi.ecm.annotation.ConfigurationPolicy;
import org.everit.osgi.ecm.annotation.Deactivate;
import org.everit.osgi.ecm.annotation.ManualService;
import org.everit.osgi.ecm.annotation.attribute.IntegerAttribute;
import org.everit.osgi.ecm.annotation.attribute.StringAttribute;
import org.everit.osgi.ecm.annotation.attribute.StringAttributeOption;
import org.everit.osgi.ecm.annotation.attribute.StringAttributes;
import org.everit.osgi.ecm.component.ComponentContext;
import org.everit.osgi.ecm.extender.ECMExtenderConstants;
import org.everit.password.encryptor.pbkdf2.Algorithm;
import org.everit.password.encryptor.pbkdf2.PBKDF2PasswordEncryptorImpl;
import org.everit.password.encryptor.pbkdf2.ecm.PBKDF2PasswordEncryptorConstants;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceRegistration;

import aQute.bnd.annotation.headers.ProvideCapability;

/**
 * ECM component for {@link CredentialEncryptor} and {@link CredentialMatcher} interface based on
 * {@link PBKDF2PasswordEncryptorImpl}.
 */
@Component(componentId = PBKDF2PasswordEncryptorConstants.SERVICE_FACTORYPID_CREDENTIAL_ENCRYPTOR,
    configurationPolicy = ConfigurationPolicy.FACTORY, label = "Everit PBKDF2 Password Encryptor",
    description = "Component for password encryption and verification based on PBKDF2.")
@ProvideCapability(ns = ECMExtenderConstants.CAPABILITY_NS_COMPONENT,
    value = ECMExtenderConstants.CAPABILITY_ATTR_CLASS + "=${@class}")
@StringAttributes({
    @StringAttribute(attributeId = Constants.SERVICE_DESCRIPTION,
        defaultValue = PBKDF2PasswordEncryptorConstants.DEFAULT_SERVICE_DESCRIPTION,
        priority = PBKDF2PasswordEncryptorComponent.P1_SERVICE_DESCRIPTION,
        label = "Service Description",
        description = "The description of this component configuration. It is used to easily "
            + "identify the service registered by this component.") })
@ManualService({ CredentialEncryptor.class, CredentialMatcher.class })
public class PBKDF2PasswordEncryptorComponent {

  public static final int P1_SERVICE_DESCRIPTION = 1;

  public static final int P2_ALGORITHM = 2;

  public static final int P3_ITERATION_COUNT = 3;

  private String algorithm;

  /**
   * Pick an iteration count that works for you. The NIST recommends at least 1,000 iterations:
   * http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf iOS 4.x reportedly uses
   * 10,000: http://blog.crackpassword.com/2010/09/smartphone-forensics-cracking-blackberry-backup-
   * passwords/
   */
  private int iterationCount;

  private ServiceRegistration<?> serviceRegistration;

  /**
   * Component activator method.
   */
  @Activate
  public void activate(final ComponentContext<PBKDF2PasswordEncryptorComponent> componentContext) {
    PBKDF2PasswordEncryptorImpl pbkdf2PasswordEncryptor =
        new PBKDF2PasswordEncryptorImpl(algorithm, iterationCount);
    Dictionary<String, Object> serviceProperties =
        new Hashtable<>(componentContext.getProperties());
    serviceRegistration =
        componentContext.registerService(
            new String[] { CredentialEncryptor.class.getName(), CredentialMatcher.class.getName() },
            pbkdf2PasswordEncryptor, serviceProperties);
  }

  /**
   * Component deactivate method.
   */
  @Deactivate
  public void deactivate() {
    if (serviceRegistration != null) {
      serviceRegistration.unregister();
    }
  }

  @StringAttribute(attributeId = PBKDF2PasswordEncryptorConstants.PROP_ALGORITHM,
      defaultValue = PBKDF2PasswordEncryptorConstants.DEFAULT_ALGORITHM, priority = P2_ALGORITHM,
      options = {
          @StringAttributeOption(label = "PBKDF2WithHmacSHA1 (since Java 1.6)",
              value = Algorithm.PBKDF2_HMAC_SHA1),
          @StringAttributeOption(label = "PBKDF2WithHmacSHA224 (since Java 1.8)",
              value = Algorithm.PBKDF2_HMAC_SHA224),
          @StringAttributeOption(label = "PBKDF2WithHmacSHA256 (since Java 1.8)",
              value = Algorithm.PBKDF2_HMAC_SHA256),
          @StringAttributeOption(label = "PBKDF2WithHmacSHA384 (since Java 1.8)",
              value = Algorithm.PBKDF2_HMAC_SHA384),
          @StringAttributeOption(label = "PBKDF2WithHmacSHA512 (since Java 1.8)",
              value = Algorithm.PBKDF2_HMAC_SHA512) },
      label = "Algorithm", description = "The secure algorithm used to encrypt the passwords.")
  public void setAlgorithm(final String algorithm) {
    this.algorithm = algorithm;
  }

  @IntegerAttribute(attributeId = PBKDF2PasswordEncryptorConstants.PROP_ITERATION_COUNT,
      defaultValue = PBKDF2PasswordEncryptorConstants.DEFAULT_ITERATION_COUNT,
      priority = P3_ITERATION_COUNT, label = "Iteration count",
      description = "The higher value increases the time necessary to brute-force the password "
          + "and also increases the encryption and matching the passwords "
          + "(i.e. the authentication will be slower in case of higher iteration count).")
  public void setIterationCount(final int iterationCount) {
    this.iterationCount = iterationCount;
  }
}
