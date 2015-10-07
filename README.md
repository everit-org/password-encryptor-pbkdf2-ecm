password-encryptor-pbkdf2-ecm
============================

ECM based components for [password-encryptor-pbkdf2][3]

#Component
The module contains one Declarative Services component. The component can be 
instantiated multiple times via Configuration Admin. The component registers 
two OSGi services: the **CredentialEncryptor** and the **CredentialMatcher** 
interfaces provided by the [credential-encryptor-api][1].

##Configuration
###Algorithm
The following algorithms are supported by the OSGi component for password 
encryption:
 - PBKDF2WithHmacSHA1 (since Java 1.6)
 - PBKDF2WithHmacSHA224 (since Java 1.8)
 - PBKDF2WithHmacSHA256 (since Java 1.8)
 - PBKDF2WithHmacSHA384 (since Java 1.8)
 - PBKDF2WithHmacSHA512 (since Java 1.8)

###Iteration
This value determines how slow the hash function will be. When computers 
become faster next year we can increase the work factor to balance it out.
Also known as work factor or security.

##Default configuration
The default and recommended setting for encryption is PBKDF2WithHmacSHA256 with
100 iterations. This will be secure enough (SHA-250) and fast enough (iteration
100) to store and match passwords. The authentication process can be kept under
1 ms with this configuration.

#Reference
[Secure Password Storage – Don’ts, dos and a Java example][2]

[1]: https://github.com/everit-org/credential-encryptor-api
[2]: http://www.javacodegeeks.com/2012/05/secure-password-storage-donts-dos-and.html
[3]: https://github.com/everit-org/password-encryptor-pbkdf2
