
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

class Main {
  

    public static void main(String[] args) {

        HttpClient client = new NettyAsyncHttpClientBuilder().build();

        HttpClient client2 = new NettyAsyncHttpClientBuilder()
    .proxy(new ProxyOptions(ProxyOptions.Type.HTTP, new InetSocketAddress("<proxy-host>", 8888)))
    .build();

    HttpClient client3 = new NettyAsyncHttpClientBuilder()
    .proxy(new ProxyOptions(ProxyOptions.Type.HTTP, new InetSocketAddress("<proxy-host>", 8888))
        .setCredentials("<username>", "<password>"))
    .build();

    HttpClient client4 = new NettyAsyncHttpClientBuilder()
    .proxy(new ProxyOptions(ProxyOptions.Type.HTTP, new InetSocketAddress("<proxy-host>", 8888))
        .setCredentials("<username>", "<password>")
        .setNonProxyHosts("<nonProxyHostRegex>"))
    .build();

//     // Constructs an HttpClient that supports both HTTP/1.1 and HTTP/2 with HTTP/2 being the preferred protocol.
// HttpClient client5 = new NettyAsyncHttpClientBuilder(reactor.netty.http.client.HttpClient.create()
//     .protocol(HttpProtocol.HTTP11, HttpProtocol.H2))
//     .build();
        System.out.println("Hello, World!");
    
    
  	Security.addProvider(new PemKeyStoreProvider());

		 String port = "";//Util.readApplicationProperties().getOrDefault("server.port", 10000).toString()";
		 int timeout =100;// NumberUtils.toInt((String) Util.readApplicationProperties().getOrDefault("server.session.timeout", "7"));

		Map<String, Object> props = new TreeMap<>();
		props.put("spring.thymeleaf.cache", false);
		props.put("spring.thymeleaf.enabled", true);
		props.put("spring.thymeleaf.prefix", "classpath:/templates/");
		props.put("spring.thymeleaf.suffix", ".html");

		props.put("server.servlet.session.cookie.http-only", true);
		props.put("server.servlet.session.cookie.max-age", TimeUnit.DAYS.toSeconds(timeout));
		props.put("server.servlet.session.timeout", TimeUnit.DAYS.toSeconds(timeout));
		props.put("server.servlet.session.persistent", true);
		props.put("server.servlet.session.cookie.name", String.format(Locale.US, "JSESSIONID-PTM_%s", port));

		props.put("spring.application.name", "ProfitTrailer Manager");
		props.put("spring.main.banner-mode", "off");
		props.put("server.compression.enabled", true);
		props.put("server.compression.mime-types", "text/html,text/xml,text/plain,text/css,text/javascript,application/javascript,application/json,application/xml");
		props.put("spring.resources.static-locations[0]", "file:src/main/resources/static/");
		props.put("spring.resources.static-locations[1]", "classpath:/static/");
		props.put("spring.resources.static-locations[2]", "file:src/main/js/");
		props.put("spring.resources.static-locations[3]", "file:classpath:/js/");

		System.setProperty("timezone", TimeZone.getDefault().getID());
		//StaticUtil.randomNumber = Util.getDateTime().toEpochSecond(ZoneOffset.UTC);


        
    }
}
