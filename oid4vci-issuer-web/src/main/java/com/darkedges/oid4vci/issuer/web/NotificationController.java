package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.issuer.IssuanceNotifications;
import com.darkedges.oid4vci.issuer.IssuerContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

/**
 * The Notification Endpoint (OID4VCI 1.0, Section 11). Behind the same resource server as the Credential Endpoint, so the token's
 * signature, issuer, audience, expiry and (for a notification token) its DPoP proof are checked before this runs. See
 * {@link IssuanceNotifications} for who may notify about what.
 */
@RestController
public class NotificationController {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final IssuanceNotifications notifications;
    private final IssuerContextResolver issuers;

    public NotificationController(IssuanceNotifications notifications, IssuerContextResolver issuers) {
        this.notifications = notifications;
        this.issuers = issuers;
    }

    @PostMapping("${oid4vci.issuer.notification-endpoint-path:/notification}")
    public ResponseEntity<Void> notification(@AuthenticationPrincipal Jwt accessToken,
                                             @RequestBody(required = false) String rawBody, HttpServletRequest request) {
        // Never open, even if an application leaves the path out of its resource server.
        if (accessToken == null) throw new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "an access token is required");
        IssuerContext context = issuers.resolve(request);
        JsonNode body;
        try {
            body = MAPPER.readTree(rawBody == null ? "" : rawBody);
        } catch (Exception e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_NOTIFICATION_REQUEST, "request body is not valid JSON", e);
        }
        boolean notificationToken = IssuanceNotifications.TOKEN_USE.equals(
                accessToken.getClaimAsString(IssuanceNotifications.TOKEN_USE_CLAIM));
        notifications.receive(context, new IssuanceNotifications.Caller(accessToken.getSubject(), notificationToken,
                        accessToken.getClaimAsString(IssuanceNotifications.NOTIFICATION_ID_CLAIM)),
                text(body, "notification_id"), text(body, "event"), Optional.ofNullable(text(body, "event_description")));
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }

    private static String text(JsonNode body, String name) {
        return body != null && body.path(name).isTextual() ? body.path(name).asText() : null;
    }
}
