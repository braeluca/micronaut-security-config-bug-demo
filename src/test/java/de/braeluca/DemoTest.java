package de.braeluca;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.cookie.SameSite;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import javax.inject.Inject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


@MicronautTest
class DemoTest {

    @Inject
    @Client("/")
    HttpClient client;

    @Test
    void testItWorks() {
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials("admin", "admin");
        HttpRequest<UsernamePasswordCredentials> request = HttpRequest.POST("/login", creds);
        HttpResponse<String> response = client.toBlocking().exchange(request, String.class);
        assertEquals(SameSite.Strict, response.getCookies().get("JWT").getSameSite().orElse(null));
        assertTrue(response.getCookies().get("JWT").isSecure());
    }

}
