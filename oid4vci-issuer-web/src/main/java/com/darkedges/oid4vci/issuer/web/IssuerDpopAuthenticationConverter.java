package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.issuer.IssuerContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.web.authentication.DPoPAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.Optional;

/**
 * Checks a DPoP proof's {@code htu} against the URL the client actually called: the request's issuer followed by its path. A
 * deployment that routes tenants by path ({@code /t/bank/credential}) hands the application the path without {@code /t/bank}, so
 * the plain request URL would never match a correct proof. Wire it with
 * {@code .dPoP(dpop -> dpop.authenticationConverter(new IssuerDpopAuthenticationConverter(issuers)))}.
 */
public final class IssuerDpopAuthenticationConverter implements AuthenticationConverter {

    private final DPoPAuthenticationConverter delegate = new DPoPAuthenticationConverter();
    private final IssuerContextResolver issuers;

    public IssuerDpopAuthenticationConverter(IssuerContextResolver issuers) {
        this.issuers = issuers;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        Optional<IssuerContext> context;
        try {
            context = issuers.current();
        } catch (RuntimeException noIssuerHere) {
            context = Optional.empty();
        }
        if (context.isEmpty()) return delegate.convert(request);
        String contextPath = request.getContextPath() == null ? "" : request.getContextPath();
        String url = context.get().url(request.getRequestURI().substring(contextPath.length()));
        return delegate.convert(new HttpServletRequestWrapper(request) {
            @Override
            public StringBuffer getRequestURL() {
                return new StringBuffer(url);
            }
        });
    }
}
