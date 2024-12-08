package com.example.oauth2_example.service;

import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Map;

/**
 * Service-Klasse zum Anfordern eines neuen Access Tokens mithilfe eines Refresh Tokens.
 */
public class TokenService {

    /**
     * Fordert ein neues Access Token an, indem ein Refresh Token verwendet wird.
     *
     * @param refreshToken Das Refresh Token, das zur Erneuerung des Access Tokens verwendet wird.
     * @param clientId Die Client-ID der Anwendung, wie in der Google-Konsole registriert.
     * @param clientSecret Das Client-Secret der Anwendung, wie in der Google-Konsole registriert.
     * @return Das neu generierte Access Token.
     * @throws RuntimeException Wenn die Anfrage fehlschlägt oder keine gültige Antwort zurückgegeben wird.
     */
    public String refreshAccessToken(String refreshToken, String clientId, String clientSecret) {
        // RestTemplate wird verwendet, um HTTP-POST-Anfragen zu senden
        RestTemplate restTemplate = new RestTemplate();

        // Der Endpunkt von Google OAuth2 zum Anfordern eines neuen Tokens
        String tokenUrl = "https://oauth2.googleapis.com/token";

        // Erstellen der Parameter für die Anfrage
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token"); // Gibt an, dass ein neues Access Token angefordert wird
        params.add("refresh_token", refreshToken); // Das Refresh Token
        params.add("client_id", clientId); // Die Client-ID der Anwendung
        params.add("client_secret", clientSecret); // Das Client-Secret der Anwendung

        // Senden der POST-Anfrage an den Token-Endpunkt von Google
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, params, Map.class);

        // Überprüfen, ob die Anfrage erfolgreich war
        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            // Das neue Access Token aus der Antwort extrahieren
            return (String) response.getBody().get("access_token");
        }

        // Fehlerbehandlung, falls die Anfrage fehlschlägt
        throw new RuntimeException("Failed to refresh access token");
    }
}
