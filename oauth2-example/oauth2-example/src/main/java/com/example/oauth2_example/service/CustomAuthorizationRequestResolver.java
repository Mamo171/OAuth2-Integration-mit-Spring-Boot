package com.example.oauth2_example.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * Eine benutzerdefinierte Implementierung des OAuth2AuthorizationRequestResolver,
 * um zusätzliche Parameter wie "access_type=offline" zu OAuth2-Anfragen hinzuzufügen.
 */
public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    // Standard-Resolver für OAuth2-Autorisierungsanfragen
    private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;

    /**
     * Konstruktor für den benutzerdefinierten Resolver.
     *
     * @param clientRegistrationRepository Repository, das die OAuth2-Client-Registrierungen enthält.
     * @param authorizationRequestBaseUri  Die Basis-URI, die für OAuth2-Autorisierungsanfragen verwendet wird.
     */
    public CustomAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, String authorizationRequestBaseUri) {
        // Initialisiert den Standard-Resolver mit den Client-Registrierungen und der Basis-URI
        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, authorizationRequestBaseUri);
    }

    /**
     * Löst eine OAuth2-Autorisierungsanfrage basierend auf der HTTP-Anfrage auf.
     *
     * @param request Die aktuelle HTTP-Anfrage.
     * @return Eine angepasste OAuth2-Autorisierungsanfrage oder null, wenn keine gültige Anfrage erstellt werden kann.
     */
    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        // Verwendet den Standard-Resolver, um eine Autorisierungsanfrage zu erstellen
        OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request);
        // Passt die Anfrage an (z. B. fügt zusätzliche Parameter hinzu)
        return customizeAuthorizationRequest(authorizationRequest);
    }

    /**
     * Löst eine OAuth2-Autorisierungsanfrage basierend auf der Client-Registrierungs-ID auf.
     *
     * @param request              Die aktuelle HTTP-Anfrage.
     * @param clientRegistrationId Die ID der Client-Registrierung.
     * @return Eine angepasste OAuth2-Autorisierungsanfrage oder null, wenn keine gültige Anfrage erstellt werden kann.
     */
    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        // Verwendet den Standard-Resolver, um eine Autorisierungsanfrage zu erstellen
        OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request, clientRegistrationId);
        // Passt die Anfrage an (z. B. fügt zusätzliche Parameter hinzu)
        return customizeAuthorizationRequest(authorizationRequest);
    }

    /**
     * Passt die OAuth2-Autorisierungsanfrage an, indem zusätzliche Parameter hinzugefügt werden.
     *
     * @param authorizationRequest Die ursprüngliche OAuth2-Autorisierungsanfrage.
     * @return Eine angepasste OAuth2-Autorisierungsanfrage oder null, wenn die ursprüngliche Anfrage null ist.
     */
    private OAuth2AuthorizationRequest customizeAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest) {
        if (authorizationRequest == null) {
            return null; // Keine Anpassung, wenn die Anfrage null ist.
        }

        // Fügt den Parameter "access_type=offline" hinzu, um einen Refresh Token zu erhalten
        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .additionalParameters(params -> params.put("access_type", "offline")) // Parameter wird hinzugefügt
                .build(); // Erstellt eine neue angepasste Autorisierungsanfrage
    }
}
