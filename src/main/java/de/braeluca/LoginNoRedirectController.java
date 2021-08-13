package de.braeluca;

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.Authenticator;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.endpoints.LoginControllerConfigurationProperties;
import io.micronaut.security.event.LoginFailedEvent;
import io.micronaut.security.event.LoginSuccessfulEvent;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.validation.Validated;
import io.reactivex.Flowable;
import io.reactivex.Single;

import javax.validation.Valid;

@Requires(beans = LoginHandler.class)
@Requires(beans = Authenticator.class)
@Controller("/login")
@Secured(SecurityRule.IS_ANONYMOUS)
@Validated
public class LoginNoRedirectController {
    protected final Authenticator authenticator;
    protected final LoginHandler loginHandler;
    protected final ApplicationEventPublisher eventPublisher;

    /**
     * @param authenticator  {@link Authenticator} collaborator
     * @param loginHandler   A collaborator which helps to build HTTP response depending on success or failure.
     * @param eventPublisher The application event publisher
     */
    public LoginNoRedirectController(Authenticator authenticator,
                           LoginHandler loginHandler,
                           ApplicationEventPublisher eventPublisher) {
        this.authenticator = authenticator;
        this.loginHandler = loginHandler;
        this.eventPublisher = eventPublisher;
    }

    /**
     * @param usernamePasswordCredentials An instance of {@link UsernamePasswordCredentials} in the body payload
     * @param request                     The {@link HttpRequest} being executed
     * @return An AccessRefreshToken encapsulated in the HttpResponse or a failure indicated by the HTTP status
     */
    @Consumes({MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON})
    @Post
    public Single<MutableHttpResponse<?>> login(@Valid @Body UsernamePasswordCredentials usernamePasswordCredentials, HttpRequest<?> request) {
        Flowable<AuthenticationResponse> authenticationResponseFlowable = Flowable.fromPublisher(authenticator.authenticate(request, usernamePasswordCredentials));

        return authenticationResponseFlowable.map(authenticationResponse -> {
            if (authenticationResponse.isAuthenticated() && authenticationResponse.getUserDetails().isPresent()) {
                UserDetails userDetails = authenticationResponse.getUserDetails().get();
                eventPublisher.publishEvent(new LoginSuccessfulEvent(userDetails));
                return loginHandler.loginSuccess(userDetails, request).status(HttpStatus.OK).body("Hello");
            } else {
                eventPublisher.publishEvent(new LoginFailedEvent(authenticationResponse));
                return loginHandler.loginFailed(authenticationResponse, request);
            }
        }).first(HttpResponse.status(HttpStatus.UNAUTHORIZED));
    }
}
