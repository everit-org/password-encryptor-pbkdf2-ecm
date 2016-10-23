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
package org.everit.password.encryptor.pbkdf2.ecm;

import org.everit.password.encryptor.pbkdf2.Algorithm;

/**
 * Constants of the PBKDF2 Password Encryptor component.
 */
public final class PBKDF2PasswordEncryptorConstants {

  public static final String DEFAULT_ALGORITHM = Algorithm.PBKDF2_HMAC_SHA256;

  public static final int DEFAULT_ITERATION_COUNT = 100;

  public static final String DEFAULT_SERVICE_DESCRIPTION =
      "Default PBKDF2 Password Encryptor Component";

  public static final String PROP_ALGORITHM = "algorithm";

  public static final String PROP_ITERATION_COUNT = "iteration.count";

  /**
   * The service factory PID of the PBKDF2 Password Encryptor component.
   */
  public static final String SERVICE_FACTORYPID_CREDENTIAL_ENCRYPTOR =
      "org.everit.password.encryptor.pbkdf2.ecm.PBKDF2PasswordEncryptor";

  private PBKDF2PasswordEncryptorConstants() {
  }

}
