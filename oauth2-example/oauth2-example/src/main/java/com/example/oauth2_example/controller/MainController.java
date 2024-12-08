package com.example.oauth2_example.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller // Markiert diese Klasse als Controller, um HTTP-Anfragen zu verarbeiten.
public class MainController {

    // Service für die Verwaltung autorisierter OAuth2-Clients
    private final OAuth2AuthorizedClientService authorizedClientService;

    // Konstruktorinjektion des OAuth2AuthorizedClientService
    public MainController(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    /**
     * Login-Seite
     * Zeigt die benutzerdefinierte Login-Seite an.
     * @return Der Name der HTML-Seite für das Login.
     */
    @GetMapping("/login")
    public String login() {
        return "login"; // Gibt die "login.html"-Seite zurück.
    }

    /**
     * Dashboard-Seite
     * Zeigt Benutzerinformationen sowie Access und Refresh Tokens an.
     * @param principal Das aktuell authentifizierte OAuth2-Benutzerobjekt.
     * @param model Das Model-Objekt zur Übergabe von Daten an die HTML-Seite.
     * @return Der Name der HTML-Seite für das Dashboard.
     */
    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal OAuth2User principal, Model model) {
        // Lädt den autorisierten OAuth2-Client für den aktuellen Benutzer
        OAuth2AuthorizedClient authorizedClient = authorizedClientService
                .loadAuthorizedClient("google", principal.getName());

        // Zugriff auf das Access Token
        String accessToken = authorizedClient.getAccessToken().getTokenValue();

        // Zugriff auf das Refresh Token (falls vorhanden)
        String refreshToken = authorizedClient.getRefreshToken() != null
                ? authorizedClient.getRefreshToken().getTokenValue()
                : "No Refresh Token";

        // Benutzerinformationen und Tokens an die HTML-Seite übergeben
        model.addAttribute("name", principal.getAttribute("name")); // Benutzername
        model.addAttribute("accessToken", accessToken); // Access Token
        model.addAttribute("refreshToken", refreshToken); // Refresh Token

        // Gibt die "dashboard.html"-Seite zurück
        return "dashboard";
    }

    /**
     * Token-Endpoint
     * Gibt Access und Refresh Tokens im Klartext zurück (nur für Debugging-Zwecke).
     * @param principal Das aktuell authentifizierte OAuth2-Benutzerobjekt.
     * @return Eine Textantwort mit Access und Refresh Tokens.
     */
    @GetMapping("/token")
    @ResponseBody // Gibt die Antwort direkt im HTTP-Body zurück (kein HTML-Template).
    public String getTokens(@AuthenticationPrincipal OAuth2User principal) {
        // Lädt den autorisierten OAuth2-Client für den aktuellen Benutzer
        OAuth2AuthorizedClient authorizedClient = authorizedClientService
                .loadAuthorizedClient("google", principal.getName());

        // Zugriff auf das Access Token
        String accessToken = authorizedClient.getAccessToken().getTokenValue();

        // Zugriff auf das Refresh Token (falls vorhanden)
        String refreshToken = authorizedClient.getRefreshToken() != null
                ? authorizedClient.getRefreshToken().getTokenValue()
                : "No Refresh Token";

        // Gibt die Tokens im Klartext zurück
        return "Access Token: " + accessToken +
                "\nRefresh Token: " + refreshToken;
    }
}
