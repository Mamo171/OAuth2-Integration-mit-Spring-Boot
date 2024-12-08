# **OAuth2-Integration mit Spring Boot**

### **OAuth2: Einführung**

**OAuth2 (Open Authorization)** ist ein standardisiertes Protokoll für den sicheren Zugriff auf Ressourcen über API-Aufrufe, ohne die Zugangsdaten eines Benutzers direkt weiterzugeben. Es wird häufig für Single-Sign-On (SSO) und API-basierte Integrationen verwendet.

#### **Hauptkonzepte im OAuth2-Protokoll:**
1. **Ressourcenserver**  
   - Der Server, der die geschützten Ressourcen des Benutzers hostet (z. B. Google Drive oder GitHub APIs).  
   - Er überprüft, ob der Client ein gültiges Access Token besitzt, bevor er Zugriff gewährt.

2. **Client (Anwendung)**  
   - Die Anwendung, die Zugriff auf die Ressourcen benötigt, z. B. eine Webanwendung oder ein Mobile App.  
   - Der Client interagiert mit dem Autorisierungsserver, um die notwendigen Tokens zu erhalten.

3. **Autorisierungsserver**  
   - Der Server, der den Benutzer authentifiziert und die Tokens ausstellt.  
   - Beispiele: Google OAuth2, Facebook Login, oder ein unternehmensinterner OAuth2-Server.  

4. **Benutzer (Ressourcenbesitzer)**  
   - Der Endbenutzer, der über die Freigabe seiner Daten entscheidet.  
   - Der Benutzer gibt dem Client (Anwendung) die Berechtigung, bestimmte Ressourcen für eine begrenzte Zeit zu verwenden.

---

#### **Flüsse im OAuth2-Protokoll:**
OAuth2 bietet verschiedene Flüsse (Flows) für unterschiedliche Anwendungsfälle, wie z. B.:
- **Authorization Code Flow:** Am häufigsten für Webanwendungen verwendet. Der Client erhält einen Code, der gegen ein Access Token ausgetauscht wird.
- **Implicit Flow:** Für clientseitige Anwendungen, bei denen kein Refresh Token erforderlich ist (wird heutzutage weniger verwendet).
- **Client Credentials Flow:** Für serverseitige Integrationen, bei denen kein Benutzer beteiligt ist (z. B. Zugriff auf System-APIs).
- **Resource Owner Password Credentials Flow:** Ermöglicht dem Client, Benutzername und Passwort direkt zu verwenden (wird nicht mehr empfohlen).

---

#### **Warum OAuth2 wichtig ist:**
- **Sicherheit:** Benutzerpasswörter werden nie an Drittanwendungen weitergegeben. Tokens bieten Zugriff nur für begrenzte Ressourcen und Zeiträume.
- **Flexibilität:** OAuth2 kann für Web-, Mobile- und API-basierte Anwendungen genutzt werden.
- **Benutzerfreundlichkeit:** Benutzer können kontrollieren, welche Daten mit welchen Anwendungen geteilt werden.

----
### **Die Rollen im OAuth2-Prozess**
1. **Ressourcenbesitzer (Benutzer):**
   - Der Benutzer, der entscheidet, ob eine Anwendung auf seine Ressourcen zugreifen darf.
   
2. **Client (Anwendung):**
   - Die Anwendung, die Zugriff auf Ressourcen benötigt (z. B. unser Spring Boot-Projekt).

3. **Ressourcenserver:**
   - Der Server, der die geschützten Ressourcen speichert (z. B. Google APIs).

4. **Autorisierungsserver:**
   - Der Server, der die Authentifizierung und die Token-Ausgabe übernimmt (z. B. Google OAuth2).

---

---

### **Tokens in OAuth2: Aufbau und Zweck**

OAuth2 verwendet zwei Haupttypen von Tokens, um den Zugriff auf geschützte Ressourcen zu verwalten: **Access Tokens** und **Refresh Tokens**. Diese Tokens gewährleisten Sicherheit und Flexibilität in der Kommunikation zwischen Clients und Servern.

---

#### **1. Access Token**

- **Was ist ein Access Token?**  
  Ein **temporärer Schlüssel**, der einem Client Zugriff auf geschützte Ressourcen gewährt. Der Client verwendet das Access Token, um sich bei einem Ressourcenserver zu authentifizieren.

- **Eigenschaften:**
  - Hat eine **kurze Gültigkeitsdauer** (z. B. 1 Stunde bei Google).
  - Kann als **Bearer Token** im HTTP-Header an API-Anfragen angehängt werden:
    ```
    Authorization: Bearer <ACCESS_TOKEN>
    ```

- **Inhalt:**  
  Das Access Token kann entweder:
  - Ein **JSON Web Token (JWT)** sein, das verschlüsselte Informationen enthält (z. B. Benutzername, Berechtigungen).
  - Oder ein zufälliger String, der vom Server gespeichert wird.

- **Verwendung:**  
  - Ermöglicht Zugriff auf geschützte Endpunkte, ohne Benutzername und Passwort erneut einzugeben.
  - Beispiel: Zugriff auf E-Mails, Fotos oder Profilinformationen eines Benutzers.

---

#### **2. Refresh Token**

- **Was ist ein Refresh Token?**  
  Ein **langfristiger Schlüssel**, der verwendet wird, um ein neues Access Token zu generieren, wenn das aktuelle abläuft.

- **Eigenschaften:**
  - Hat eine **längere Gültigkeitsdauer** als Access Tokens.
  - Kann mehrfach verwendet werden, bis es widerrufen oder ungültig wird.
  - Wird nur ausgegeben, wenn `access_type=offline` in der OAuth2-Anfrage gesetzt ist.

- **Verwendung:**  
  - Erneuert Access Tokens, ohne dass der Benutzer erneut authentifiziert werden muss.
  - Beispiel: Wenn ein Benutzer eine Anwendung nach Stunden öffnet, kann ein neues Access Token angefordert werden, ohne den Login-Prozess zu durchlaufen.

- **Inhalt:**  
  - Ein sicherer, verschlüsselter String, der vom Autorisierungsserver ausgegeben wird.

---

### **Struktur eines JWT Access Tokens**

Wenn ein **JSON Web Token (JWT)** als Access Token verwendet wird, besteht es aus drei Teilen, die durch Punkte (`.`) getrennt sind:

1. **Header:**  
   - Enthält Metadaten über das Token, wie den Typ (`JWT`) und den Algorithmus zur Signatur (`HS256` oder `RS256`).
   - Beispiel:
     ```json
     {
       "alg": "RS256",
       "typ": "JWT"
     }
     ```

2. **Payload:**  
   - Enthält die eigentlichen Daten des Benutzers, wie:
     - Benutzer-ID (`sub`)
     - Scopes (`scope`)
     - Ablaufzeit (`exp`)
   - Beispiel:
     ```json
     {
       "sub": "1234567890",
       "name": "John Doe",
       "email": "john.doe@example.com",
       "scope": "email profile",
       "exp": 1672531199
     }
     ```

3. **Signature:**  
   - Eine kryptografische Signatur, die die Integrität des Tokens sicherstellt. Sie wird mit einem geheimen Schlüssel oder einem öffentlichen/privaten Schlüsselpaar erstellt.
   - Beispiel (vereinfacht):
     ```
     HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)
     ```

**Vorteile von JWT-basierten Access Tokens:**
- Benutzerinformationen können direkt aus dem Token ausgelesen werden (ohne zusätzliche API-Anfrage).
- Die Integrität des Tokens wird durch die Signatur sichergestellt.

---

### **Zusammenfassung: Access Token vs. Refresh Token**

| **Eigenschaft**        | **Access Token**                     | **Refresh Token**                     |
|-------------------------|--------------------------------------|---------------------------------------|
| **Zweck**              | Zugriff auf geschützte Ressourcen    | Erneuerung eines Access Tokens       |
| **Gültigkeitsdauer**    | Kurzfristig (z. B. 1 Stunde)         | Langfristig (z. B. bis widerrufen)   |
| **Verwendung**         | In API-Aufrufen als Bearer Token     | Im Hintergrund für Access Token Erneuerung |
| **Sicherheit**         | Kann bei Verlust missbraucht werden  | Muss sicher gespeichert werden        |

---

Hier ist eine detaillierte und technisch geschriebene Erklärung der praktischen Implementierung in Spring Boot:

---

## **Praktische Implementierung in Spring Boot**

### **Ziel der Implementierung**
Das Ziel dieser Implementierung ist es, eine Spring-Boot-Anwendung zu erstellen, die OAuth2 für die Benutzeranmeldung integriert. Die Anwendung ermöglicht Benutzern, sich über Google anzumelden, und zeigt nach erfolgreicher Authentifizierung die Access Tokens und Refresh Tokens an, um die korrekte Konfiguration und Funktionsweise von OAuth2 zu validieren. Diese Tokens können später genutzt werden, um geschützte Ressourcen zu konsumieren oder die Sitzung zu verlängern.

---

### **Schritte der Implementierung**

#### **1. Einrichtung des Projekts**
- **Spring Boot Initializer:**  
  Ein neues Spring-Boot-Projekt wurde erstellt mit den folgenden Abhängigkeiten:
  - `Spring Web`
  - `Spring Security`
  - `Spring OAuth2 Client`
- **Projektstruktur:**  
  Die grundlegende Struktur des Projekts enthält folgende Bestandteile:
  - **`config/`**: Sicherheitskonfiguration.
  - **`controller/`**: Steuerung der Benutzerinteraktionen.
  - **`service/`**: Verarbeitung und Erweiterung der OAuth2-Logik.
  - **`templates/`**: HTML-Seiten für Login und Dashboard.

---

#### **2. OAuth2-Konfiguration**
- **Google als OAuth2-Provider registrieren:**  
  Die `application.properties`-Datei enthält die notwendigen Konfigurationen, um Google als Autorisierungsserver zu integrieren:
  ```properties
  spring.security.oauth2.client.registration.google.client-id=<CLIENT_ID>
  spring.security.oauth2.client.registration.google.client-secret=<CLIENT_SECRET>
  spring.security.oauth2.client.registration.google.redirect-uri=http://localhost:8080/login/oauth2/code/google
  spring.security.oauth2.client.registration.google.scope=openid, email, profile
  spring.security.oauth2.client.registration.google.authorization-grant-type=authorization_code
  ```
- **Wichtige Parameter:**
  - **`client-id` und `client-secret`:** Identifizieren die Anwendung beim Google OAuth2-Server.
  - **`redirect-uri`:** Gibt die URI an, zu der Google den Benutzer nach erfolgreichem Login weiterleitet.
  - **`scope`:** Definiert die Berechtigungen, die die Anwendung vom Benutzer anfordert (z. B. Zugriff auf E-Mail und Profil).

---

#### **3. Sicherheitskonfiguration**
- Die Sicherheitslogik wurde in einer `SecurityConfig`-Klasse definiert, um:
  - Öffentliche und geschützte Endpunkte zu trennen.
  - Den OAuth2-Login-Flow zu integrieren.
  - Einen benutzerdefinierten Resolver für OAuth2-Requests zu verwenden.

- **Details der Konfiguration:**
  - Öffentliche Endpunkte wie `/login` und statische Ressourcen (`/css/**`, `/js/**`) sind für jeden Benutzer zugänglich.
  - Geschützte Endpunkte wie `/dashboard` erfordern eine Authentifizierung.
  - Ein benutzerdefinierter `AuthorizationRequestResolver` wurde implementiert, um den Parameter `access_type=offline` zur OAuth2-Anfrage hinzuzufügen. Dadurch wird der Erhalt eines Refresh Tokens sichergestellt.

---

#### **4. Benutzer-Login und Token-Anzeige**
- Nach der Anmeldung wird der Benutzer auf ein Dashboard weitergeleitet, das Folgendes anzeigt:
  - **Access Token:** Temporär gültig und wird verwendet, um geschützte Ressourcen zu konsumieren.
  - **Refresh Token:** Langfristig gültig und ermöglicht die Erneuerung des Access Tokens.

- **Token-Anzeige im Dashboard:**  
  Eine einfache HTML-Seite zeigt die Tokens an:
  ```html
  <h1>Willkommen, <span th:text="${name}"></span>!</h1>
  <p>Access Token:</p>
  <textarea readonly th:text="${accessToken}"></textarea>
  <p>Refresh Token:</p>
  <textarea readonly th:text="${refreshToken}"></textarea>
  <a href="/logout">Abmelden</a>
  ```
  Dies dient ausschließlich zu Debugging-Zwecken und sollte in einer Produktionsumgebung entfernt oder abgesichert werden.

---

#### **5. Token-Verwaltung**
- Ein zusätzlicher Endpunkt `/token` gibt die Tokens als Text zurück, um ihre Gültigkeit und den Erhalt des Refresh Tokens zu prüfen.
- Die Access Tokens können direkt für API-Aufrufe genutzt werden, während Refresh Tokens zur Erneuerung von Access Tokens verwendet werden.

---

### **Test mit Postman**

1. **Test des Access Tokens:**
   - Nach erfolgreichem Login wird das Access Token aus dem Dashboard kopiert und in Postman getestet:
     - **Methode:** `GET`
     - **URL:** Eine geschützte API (z. B. Google APIs).
     - **Header:**
       ```
       Authorization: Bearer <ACCESS_TOKEN>
       ```
   - Ergebnis: Die API sollte eine erfolgreiche Antwort zurückgeben.

2. **Test des Refresh Tokens:**
   - Mit dem Refresh Token kann ein neues Access Token angefordert werden:
     - **Methode:** `POST`
     - **URL:** `https://oauth2.googleapis.com/token`
     - **Body (x-www-form-urlencoded):**
       ```
       grant_type=refresh_token
       refresh_token=<REFRESH_TOKEN>
       client_id=<CLIENT_ID>
       client_secret=<CLIENT_SECRET>
       ```
   - Ergebnis: Ein neues Access Token wird in der Antwort zurückgegeben.

---

### **Herausforderungen**

1. **Erhalt des Refresh Tokens:**  
   Der Parameter `access_type=offline` musste explizit hinzugefügt werden, da Google standardmäßig keinen Refresh Token ausstellt.

2. **Kein Refresh Token bei aktiver Berechtigung:**  
   Falls die Anwendung bereits autorisiert ist, gibt Google keinen neuen Refresh Token aus. Manuelles Widerrufen der Berechtigung war notwendig.

3. **Sichere Token-Verwaltung:**  
   Es musste sichergestellt werden, dass Tokens nicht im Frontend oder an unsicheren Orten gespeichert werden.

4. **Token-Ablauf:**  
   Access Tokens laufen schnell ab, was die automatische Erneuerung mit dem Refresh Token erforderlich macht.

---

### **Best Practices**

1. **Minimale Berechtigungen anfordern:**  
   Nur die notwendigen Scopes wie `openid`, `email`, `profile` sollten angefordert werden, um Benutzervertrauen zu wahren.

2. **Sichere Token-Speicherung:**  
   Tokens sollten niemals im Frontend oder im lokalen Speicher gespeichert werden. Sie sollten serverseitig verwaltet und verschlüsselt gespeichert werden.

3. **HTTPS verwenden:**  
   Alle Anfragen und Token-Übertragungen müssen ausschließlich über HTTPS erfolgen.

4. **Logout korrekt implementieren:**  
   Beim Logout sollten Access Tokens und Refresh Tokens widerrufen werden.

5. **Automatische Token-Erneuerung:**  
   Eine Logik zur automatischen Erneuerung von Access Tokens vor Ablaufzeit sollte implementiert werden.

6. **Monitoring und Logging:**  
   Die Nutzung von Tokens sollte überwacht werden, um Missbrauch zu verhindern (z. B. durch verdächtige IP-Adressen oder wiederholte Anfragen).

---

### **Zusammenfassung**
Die Implementierung hat eine sichere OAuth2-Integration in Spring Boot ermöglicht. Mit OAuth2 wurden Benutzer sicher authentifiziert, und die Tokens wurden erfolgreich zur weiteren Nutzung und Prüfung angezeigt. Diese Grundlage kann für Anwendungen verwendet werden, die externe Autorisierungsserver nutzen und Zugriff auf geschützte Ressourcen benötigen.

--- 
