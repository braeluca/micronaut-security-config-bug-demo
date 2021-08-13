package de.braeluca;

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;

import javax.annotation.security.PermitAll;

@Controller
@PermitAll
//@Secured(SecurityRule.IS_AUTHENTICATED)
public class DefaultController {

    @Get
    public String hello() {
        return "Hello World!";
    }
}
