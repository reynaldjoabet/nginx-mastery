
import com.azure.core.http.HttpClient;
import com.azure.core.http.ProxyOptions;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.security.Security;
import de.dentrassi.crypto.pem.PemKeyStoreProvider;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.Locale;
import java.util.TimeZone;
import java.time.ZoneOffset;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URI;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;

import de.dentrassi.crypto.pem.PemKeyStoreProvider;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
class SSLSupport {
  
   public static final String NONE = "NONE";
   private String keystoreProvider = TransportConstants.DEFAULT_KEYSTORE_PROVIDER;
   private String keystoreType = TransportConstants.DEFAULT_KEYSTORE_TYPE;
   private String keystorePath = TransportConstants.DEFAULT_KEYSTORE_PATH;
   private String keystorePassword = TransportConstants.DEFAULT_KEYSTORE_PASSWORD;
   private String truststoreProvider = TransportConstants.DEFAULT_TRUSTSTORE_PROVIDER;
   private String truststoreType = TransportConstants.DEFAULT_TRUSTSTORE_TYPE;
   private String truststorePath = TransportConstants.DEFAULT_TRUSTSTORE_PATH;
   private String truststorePassword = TransportConstants.DEFAULT_TRUSTSTORE_PASSWORD;
   private String crlPath = TransportConstants.DEFAULT_CRL_PATH;
   private String sslProvider = TransportConstants.DEFAULT_SSL_PROVIDER;
   private boolean trustAll = TransportConstants.DEFAULT_TRUST_ALL;
   private String trustManagerFactoryPlugin = TransportConstants.DEFAULT_TRUST_MANAGER_FACTORY_PLUGIN;
   private String keystoreAlias = TransportConstants.DEFAULT_KEYSTORE_ALIAS;


   public String getKeystoreType() {
      return keystoreType;
   }


   public String getKeystorePath() {
      return keystorePath;
   }


   public String getKeystorePassword() {
      return keystorePassword;
   }


   public String getKeystoreAlias() {
      return keystoreAlias;
   }



   public String getTruststoreProvider() {
      return truststoreProvider;
   }


   public String getTruststoreType() {
      return truststoreType;
   }



   public String getTruststorePath() {
      return truststorePath;
   }

 

   public String getTruststorePassword() {
      return truststorePassword;
   }


   public String getCrlPath() {
      return crlPath;
   }

   public SSLSupport setCrlPath(String crlPath) {
      this.crlPath = crlPath;
      return this;
   }

   public String getSslProvider() {
      return sslProvider;
   }

   public SSLSupport setSslProvider(String sslProvider) {
      this.sslProvider = sslProvider;
      return this;
   }

   public boolean isTrustAll() {
      return trustAll;
   }

   public SSLSupport setTrustAll(boolean trustAll) {
      this.trustAll = trustAll;
      return this;
   }

   public String getTrustManagerFactoryPlugin() {
      return trustManagerFactoryPlugin;
   }

   public SSLSupport setTrustManagerFactoryPlugin(String trustManagerFactoryPlugin) {
      this.trustManagerFactoryPlugin = trustManagerFactoryPlugin;
      return this;
   }

   public SSLContext createContext() throws Exception {
      SSLContext context = SSLContext.getInstance("TLS");
      KeyManager[] keyManagers = loadKeyManagers();
      TrustManager[] trustManagers = loadTrustManagers();
      context.init(keyManagers, trustManagers, new SecureRandom());
      return context;
   }



   public static String[] parseCommaSeparatedListIntoArray(String suites) {
      String[] cipherSuites = suites.split(",");
      for (int i = 0; i < cipherSuites.length; i++) {
         cipherSuites[i] = cipherSuites[i].trim();
      }
      return cipherSuites;
   }

   public static String parseArrayIntoCommandSeparatedList(String[] suites) {
      StringBuilder supportedSuites = new StringBuilder();

      for (String suite : suites) {
         supportedSuites.append(suite);
         supportedSuites.append(", ");
      }

      // trim the last 2 characters (i.e. unnecessary comma and space)
      return supportedSuites.delete(supportedSuites.length() - 2, supportedSuites.length()).toString();
   }

   private TrustManagerFactory loadTrustManagerFactory() throws Exception {
      if (trustManagerFactoryPlugin != null) {
         return null;
      } else if (trustAll) {
         //This is useful for testing but not should be used outside of that purpose
         return InsecureTrustManagerFactory.INSTANCE;
      } else if ((truststorePath == null || truststorePath.isEmpty() || truststorePath.equalsIgnoreCase(NONE)) && (truststoreProvider == null || !truststoreProvider.toUpperCase().contains("PKCS11"))) {
         return null;
      } else {
         TrustManagerFactory trustMgrFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
         KeyStore trustStore = SSLSupport.loadKeystore(truststoreProvider, truststoreType, truststorePath, truststorePassword);
         boolean ocsp = Boolean.valueOf(Security.getProperty("ocsp.enable"));

         boolean initialized = false;
         if ((ocsp || crlPath != null) && TrustManagerFactory.getDefaultAlgorithm().equalsIgnoreCase("PKIX")) {
            PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustStore, new X509CertSelector());
            if (crlPath != null) {
               pkixParams.setRevocationEnabled(true);
               Collection<? extends CRL> crlList = loadCRL();
               if (crlList != null) {
                  pkixParams.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(crlList)));
               }
            }
            trustMgrFactory.init(new CertPathTrustManagerParameters(pkixParams));
            initialized = true;
         }

         if (!initialized) {
            trustMgrFactory.init(trustStore);
         }
         return trustMgrFactory;
      }
   }

   private TrustManager[] loadTrustManagers() throws Exception {
      TrustManagerFactory trustManagerFactory = loadTrustManagerFactory();
      if (trustManagerFactory == null) {
         return null;
      }
      return trustManagerFactory.getTrustManagers();
   }

   private Collection<? extends CRL> loadCRL() throws Exception {
      if (crlPath == null) {
         return null;
      }
      URL resource = validateStoreURL(crlPath);
      try (InputStream is = resource.openStream()) {
         return CertificateFactory.getInstance("X.509").generateCRLs(is);
      }
   }

   private static KeyStore loadKeystore(final String keystoreProvider,
                                        final String keystoreType,
                                        final String keystorePath,
                                        final String keystorePassword) throws Exception {
      checkPemProviderLoaded(keystoreType);
      KeyStore ks = keystoreProvider == null ? KeyStore.getInstance(keystoreType) : KeyStore.getInstance(keystoreType, keystoreProvider);
      InputStream in = null;
      try {
         if (keystorePath != null && !keystorePath.isEmpty() && !keystorePath.equalsIgnoreCase(NONE)) {
            URL keystoreURL = SSLSupport.validateStoreURL(keystorePath);
            in = keystoreURL.openStream();
         }
         ks.load(in, keystorePassword == null ? null : keystorePassword.toCharArray());
      } finally {
         if (in != null) {
            try {
               in.close();
            } catch (IOException ignored) {
            }
         }
      }
      return ks;
   }

   public static void checkPemProviderLoaded(String keystoreType) {
      if (keystoreType != null && keystoreType.startsWith("PEM")) {
         if (Security.getProvider("PEM") == null) {
            Security.insertProviderAt(new PemKeyStoreProvider(), Integer.parseInt(System.getProperty("artemis.pemProvider.insertAt", "0")));
         }
      }
   }

   private KeyManager[] loadKeyManagers() throws Exception {
      KeyManagerFactory factory = loadKeyManagerFactory();
      if (factory == null) {
         return null;
      }
      KeyManager[] keyManagers = factory.getKeyManagers();
      if (keystoreAlias != null) {
         for (int i = 0; i < keyManagers.length; i++) {
            if (keyManagers[i] instanceof X509KeyManager) {
               keyManagers[i] = null;//new AliasedKeyManager((X509KeyManager) keyManagers[i], keystoreAlias);
            }
         }
      }
      return keyManagers;
   }

   private KeyManagerFactory loadKeyManagerFactory() throws Exception {
      if ((keystorePath == null || keystorePath.isEmpty() || keystorePath.equalsIgnoreCase(NONE)) && (keystoreProvider == null || !keystoreProvider.toUpperCase().contains("PKCS11"))) {
         return null;
      } else {
         KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
         KeyStore ks = SSLSupport.loadKeystore(keystoreProvider, keystoreType, keystorePath, keystorePassword);
         kmf.init(ks, keystorePassword == null ? null : keystorePassword.toCharArray());
         return kmf;
      }
   }

   private static URL validateStoreURL(final String storePath) throws Exception {
      assert storePath != null;

      // First see if this is a URL
      try {
         return new URI(storePath).toURL();
      } catch (MalformedURLException e) {
         File file = new File(storePath);
         if (file.exists() && file.isFile()) {
            return file.toURI().toURL();
         } else {
            URL url = findResource(storePath);
            if (url != null) {
               return url;
            }
         }
      }

      throw new Exception("Failed to find a store at " + storePath);
   }

   /**
    * This seems duplicate code all over the place, but for security reasons we can't let something like this to be open in a
    * utility class, as it would be a door to load anything you like in a safe VM.
    * For that reason any class trying to do a privileged block should do with the AccessController directly.
    */
   private static URL findResource(final String resourceName) {
      return null;
   }


   private KeyManagerFactory getKeyManagerFactory(KeyStore keyStore, char[] keystorePassword) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
      KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      keyManagerFactory.init(keyStore, keystorePassword);
      return keyManagerFactory;
   }



}