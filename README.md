
# Types of Authentication

## 1. Basic Authentication

* **What**: Uses a username and password in the Authorization header (Base64 encoded).
* **When to Use**: For simple, low-security applications or internal APIs.
* **Why**: Easy to implement and sufficient for minimal security needs.
* **Where (Implementation)**: API endpoints that don't handle sensitive data.
* **How (Spring Boot Example)**:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .anyRequest().authenticated()
            .and()
            .httpBasic();
    }
}
```

---

## 2. JWT (JSON Web Token) Authentication

* **What**: Token-based authentication; the token is passed in the Authorization header (Bearer `<token>`).
* **When to Use**: For stateless applications (REST APIs) and scalable microservices.
* **Why**: No need to store session data; tokens are self-contained and secure.
* **Where**: E-Commerce (User Login) and Real Estate (Blog Module Access).
* **How**:

```java
// Generate JWT
String token = Jwts.builder()
    .setSubject(user.getUsername())
    .setIssuedAt(new Date())
    .setExpiration(new Date(System.currentTimeMillis() + 86400000))  // 1 day expiry
    .signWith(SignatureAlgorithm.HS512, "secretKey")
    .compact();
```

---

## 3. OAuth 2.0 Authentication

* **What**: Delegated access; allows third-party logins (Google, Facebook).
* **When to Use**: For apps requiring social login or third-party resource access.
* **Why**: Secure, reduces friction for users, avoids managing passwords directly.
* **Where**: Applications with user-generated content or mobile apps.
* **How (Spring Boot)**:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.oauth2Login();
    }
}
```

---

## 4. Session-Based Authentication

* **What**: Session is created upon login and managed server-side (JSESSIONID).
* **When to Use**: Traditional web apps with multiple pages.
* **Why**: Simple and effective for stateful apps.
* **Where**: Admin dashboards or portals.
* **How**:

```java
http
    .authorizeRequests()
        .anyRequest().authenticated()
    .and()
    .formLogin();
```

---

## 5. Token-Based Authentication (Bearer Tokens)

* **What**: Tokens issued by the server and passed with each request.
* **When to Use**: Mobile apps, SPAs, REST APIs.
* **Why**: Stateless, reduces load on the server, improves performance.
* **Where**: E-Commerce checkout flow.
* **How**: Similar to JWT, but tokens may not be self-contained.

---

## 6. LDAP (Lightweight Directory Access Protocol)

* **What**: Authentication against a directory service (e.g., Active Directory).
* **When to Use**: Enterprise apps with centralized identity management.
* **Why**: Simplifies user management across large organizations.
* **Where**: Internal enterprise applications.
* **How**:

```java
@Override
public void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
        .ldapAuthentication()
        .userDnPatterns("uid={0},ou=users")
        .contextSource()
        .url("ldap://localhost:8389/dc=springframework,dc=org");
}
```

---

## 7. Multi-Factor Authentication (MFA)

* **What**: Requires multiple forms of verification (password + OTP).
* **When to Use**: High-security applications (banking, healthcare).
* **Why**: Enhances security by adding extra verification steps.
* **Where**: Sensitive portals (Real Estate admin panel).
* **How**: Combine with OTP via SMS or email.

---

## 8. SAML (Security Assertion Markup Language)

* **What**: XML-based authentication for single sign-on (SSO).
* **When to Use**: SSO across enterprise apps.
* **Why**: Simplifies user access across platforms.
* **Where**: Enterprise intranet portals.

---

## 9. API Key Authentication

* **What**: API key passed in headers for each request.
* **When to Use**: For public APIs, services, and third-party integrations.
* **Why**: Lightweight and straightforward.
* **Where**: Real Estate property listing API (third-party access).
* **How**:

```java
if (!apiKey.equals("expectedKey")) {
    throw new UnauthorizedAccessException("Invalid API Key");
}
```

---

## 10. Digest Authentication

* **What**: Hash-based authentication (encrypts credentials).
* **When to Use**: Basic security with less exposure than Basic Auth.
* **Why**: More secure than Basic Auth but less complex than OAuth.
* **Where**: Internal APIs with moderate sensitivity.

---

## When to Choose Which:

* **JWT/OAuth2**: For stateless, scalable apps (microservices, mobile).
* **Session-Based**: Traditional web apps (multi-page forms).
* **MFA/OAuth2**: High-security apps.
* **API Keys**: Public APIs, third-party access.
* **LDAP/SAML**: Enterprise environments.

---

# TWO TYPES OF AUTHENTICATION USED IN PROJECT

---

## 1. Session-Based Authentication

### Overview:
Session-based authentication is a traditional method where the server maintains the state of the authenticated user. The session is created when a user logs in and destroyed when the user logs out.

### How Session-Based Authentication Works:

1. **User Login**:
   * The user submits credentials (username/password) through a login form.
2. **Verification**:
   * The server verifies the credentials by checking them against the database.
3. **Session Creation**:
   * If credentials are correct, the server creates a session and stores it (in-memory or database).
   * A session ID is generated and sent to the client in the form of a cookie.
4. **Subsequent Requests**:
   * The client sends the session ID (cookie) in the header with every request.
   * The server checks the session store to validate the session ID.
5. **Access Granted**:
   * If the session is valid, the user is authenticated, and access is granted.
6. **Session Expiration**:
   * The session can expire after a certain period of inactivity or when the user logs out.

### Pros and Cons:

#### Pros:
* Simple to implement.
* Session data is securely stored on the server.
* Cookies can be protected with HTTP-only and Secure flags.

#### Cons:
* Scalability Issues: Session data is stored on the server, making scaling difficult as the user base grows.
* Stateful: Requires server memory or database for each session.
* Load Balancing Challenges: Sticky sessions or distributed caching (Redis) are needed for load balancing.
* Security Risks: Vulnerable to session hijacking or cross-site scripting (XSS) if cookies are not secured.

### When to Use Session-Based Authentication:
* Small to Medium Applications where scalability isn’t a major concern.
* Traditional monolithic web applications.
* Applications with minimal microservices or APIs.

### Example Implementation (Spring Security – Java):

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/login", "/register").permitAll()
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .loginPage("/login")
            .defaultSuccessUrl("/dashboard", true)
            .and()
            .logout()
            .logoutSuccessUrl("/login?logout")
            .invalidateHttpSession(true);
    }
}
```

---

## 2. Token-Based Authentication (JWT – JSON Web Token)

### Overview:
Token-based authentication uses a token (usually a JWT) that is issued after successful login. This token contains user details and is passed with every request. Unlike session-based authentication, the server does not store user sessions.

### How Token-Based Authentication Works:

1. **User Login**:
   * The user submits credentials (username/password) via an API call.
2. **Verification**:
   * The server verifies the credentials.
3. **Token Generation**:
   * Upon successful verification, the server generates a JWT (JSON Web Token) containing user information (claims).
   * The JWT is sent to the client.
4. **Subsequent Requests**:
   * The client stores the token (usually in localStorage or sessionStorage).
   * On each request, the token is sent in the Authorization header.
5. **Validation**:
   * The server validates the JWT by verifying the signature and extracts user details from the token.
6. **Access Granted**:
   * If the token is valid, access is granted.

### Pros and Cons:

#### Pros:
* Stateless: No session storage is required on the server.
* Scalable: Ideal for distributed systems and microservices.
* Cross-Domain: Tokens can be sent to different services or domains.
* Efficient: Fast authentication without querying the database for every request.

#### Cons:
* Token Revocation: JWTs cannot be revoked easily after logout.
* Security Risks: If a token is compromised, it can be reused until it expires.
* Size: Tokens are larger than session IDs.

### When to Use Token-Based Authentication:
* Microservices Architecture or distributed systems.
* Mobile or Single Page Applications (SPA).
* APIs that require scalability and stateless authentication.

### Example Implementation (Spring Boot – JWT):

1. **Generate JWT**:

```java
@Component
public class JwtUtil {

    private String secret = "secretKey";

    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }
}
```

2. **Validate Token**:

```java
public Boolean validateToken(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
}
```

### Differences Between Session-Based and Token-Based Authentication:
```
------------------------------------------------------------------------------------------------------------------
| Feature                   | Session-Based                             | Token-Based (JWT)                      |
| --------------------------| ----------------------------------------- | ---------------------------------------|
| **State**                 | Stateful (server stores session)          | Stateless (no server storage)          |
| **Scalability**           | Less scalable                             | Highly scalable                        |
| **Performance**           | Slower (DB calls for session validation)  | Faster (no DB calls for every request) |
| **Security**              | Vulnerable to session hijacking           | Vulnerable to token theft              |
| **Token Revocation**      | Session can be invalidated                | Token cannot be revoked easily         |
| **Storage (Client-Side)** | Cookie                                    | LocalStorage / SessionStorage          |
| **Cross-Domain**          | Limited to same-origin                    | Works across domains                   |
| **Use Case**              | Web applications                          | Mobile apps, SPAs, APIs, Microservices |
------------------------------------------------------------------------------------------------------------------
```

---

## Which Authentication Was Used in My Projects?

1. **E-Commerce Project**:
    * JWT Token-Based Authentication – Scalable, secure API authentication for user login and secure endpoints.

2. **Real Estate Project (Blog Module)**:
    * JWT Token-Based Authentication – Used for managing blog post creation, editing, and user login.

### Why JWT Was Chosen:
* **Scalability** – The project required a distributed architecture.
* **Statelessness** – APIs needed to authenticate users without relying on server-side session storage.
* **Security** – JWT allowed for encrypted claims and secure token transmission.
```

This `ARTICLE` includes both types of authentication you used in your projects along with examples, explanations, and comparisons between session-based and token-based (JWT) authentication.
```




## Click here to get in touch with me :
<a href="https://github.com/Tech-Hubs" target="_blank">PrabhatDevLab</a>, <a href="https://hugs-4-bugs.github.io/myResume/" target="_blank">PrabhatKumar.com</a>, <a href="https://www.linkedin.com/in/prabhat-kumar-6963661a4/" target="_blank">LinkedIn</a>, <a href="https://stackoverflow.com/users/19520484/prabhat-kumar" target="_blank">Stackoverflow</a>, <a href="https://github.com/Hugs-4-Bugs" target="_blank">GitHub</a>, <a href="https://leetcode.com/u/Hugs-2-Bugs/" target="_blank">LeetCode</a>, <a href="https://www.hackerrank.com/profile/Prabhat_7250" target="_blank">HackerRank</a>, <a href="https://www.geeksforgeeks.org/user/stealthy_prabhat/" target="_blank">GeeksforGeeks</a>, <a href="https://hugs-4-bugs.github.io/AlgoByPrabhat/" target="_blank">AlgoByPrabhat</a>, <a href="http://hugs-4-bugs.github.io/Sharma-AI/" target="_blank">SHARMA AI</a>,  <a href="https://linktr.ee/_s_4_sharma" target="_blank">About Me</a>, <a href="https://www.instagram.com/_s_4_sharma/" target="_blank">Instagram</a>, <a href="https://x.com/kattyPrabhat" target="_blank">Twitter</a>

<b>Click here to get in touch with me :</b>
<a href="https://github.com/Tech-Hubs" target="_blank">PrabhatDevLab</a>, 
<a href="https://hugs-4-bugs.github.io/myResume/" target="_blank">PrabhatKumar.com</a>, 
<a href="https://www.linkedin.com/in/prabhat-kumar-6963661a4/" target="_blank">LinkedIn</a>, 
<a href="https://stackoverflow.com/users/19520484/prabhat-kumar" target="_blank">Stackoverflow</a>, 
<a href="https://github.com/Hugs-4-Bugs" target="_blank">GitHub</a>, 
<a href="https://leetcode.com/u/Hugs-2-Bugs/" target="_blank">LeetCode</a>, 
<a href="https://www.hackerrank.com/profile/Prabhat_7250" target="_blank">HackerRank</a>, 
<a href="https://www.geeksforgeeks.org/user/stealthy_prabhat/" target="_blank">GeeksforGeeks</a>, 
<a href="https://hugs-4-bugs.github.io/AlgoByPrabhat/" target="_blank">AlgoByPrabhat</a>, 
<a href="http://hugs-4-bugs.github.io/Sharma-AI/" target="_blank">SHARMA AI</a>,  
<a href="https://linktr.ee/_s_4_sharma" target="_blank">About Me</a>, 
<a href="https://www.instagram.com/_s_4_sharma/" target="_blank">Instagram</a>, 
<a href="https://x.com/kattyPrabhat" target="_blank">Twitter</a>



<p>Happy Learning! 📚✨ Keep exploring and growing your knowledge! 🚀😊</p>
