This folder contains JKS KeyStores from within the Elytron project, unless 
absolutely required update files within the Elytron project and copy them over 
so we only need to maintain them in one location.

All keystores and entries share the same password 'Elytron'.

ca.truststore - Contains the self signed certificate of the certificate authority.
scarab.keystore - Contains an alias 'scarab'
ladybird.keystore - Contains and alias 'ladybird'

The keystore 'tiger.keystore' can be used in tests where only beetles are valid. To re-create it, please execute the following command:

    keytool -keystore tiger.keystore -genkey -alias tiger

Please, use 'Elytron' as both keystore and key passwords. Regarding the certificate info, you can leave all fields in blank:

What is your first and last name?
  [Unknown]:
What is the name of your organizational unit?
  [Unknown]:
What is the name of your organization?
  [Unknown]:
What is the name of your City or Locality?
  [Unknown]:
What is the name of your State or Province?
  [Unknown]:
What is the two-letter country code for this unit?
  [Unknown]:
Is CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown correct?
  [no]:  yes