/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.WebGoat;
import org.owasp.webgoat.container.i18n.Language;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.web.context.WebApplicationContext;

/**
 * Pruebas negativas de seguridad contra un único endpoint protegido: {@code GET
 * /service/admin/users/{username}} (ver {@link AdminController}).
 *
 * <p>Cada prueba apunta a una familia de controles y se espera que falle (quede roja) si se elimina
 * el control correspondiente de la aplicación:
 *
 * <ul>
 *   <li><b>Autorización</b> – un usuario autenticado normal (sin la autoridad {@code
 *       WEBGOAT_ADMIN}) debe recibir 403. Control: la regla de URL {@code
 *       hasAuthority('WEBGOAT_ADMIN')} en {@code WebSecurityConfig} más las comprobaciones a nivel
 *       de método {@code @PreAuthorize}.
 *   <li><b>Autenticación</b> – una petición anónima debe recibir 401 (AJAX) o un 302 a {@code
 *       /login} (navegador); una sesión inexistente o inválida nunca debe autenticarse. Control:
 *       {@code anyRequest().authenticated()} y {@code AjaxAuthenticationEntryPoint}.
 *   <li><b>Validación de entradas</b> – los payloads de inyección SQL / XSS en la variable de ruta
 *       {@code {username}} deben rechazarse (404) sin ejecutarse ni reflejarse. Control: acceso a
 *       datos por comparación segura en memoria / consultas parametrizadas, nunca por concatenación.
 *   <li><b>Manejo de errores</b> – las respuestas de error deben ser controladas (estado correcto,
 *       mensaje genérico) y no deben filtrar un stack trace. Control: {@code
 *       spring.web.error.include-stacktrace=never}.
 * </ul>
 *
 * <p>Las tres primeras pruebas corren por MockMvc construido con la cadena real de filtros de
 * Spring Security ({@code springSecurity()}) usando sesiones obtenidas con form logins reales. La
 * prueba de manejo de errores corre contra el servidor embebido real (puerto aleatorio) porque el
 * comportamiento del stack trace solo se materializa a través del error dispatch del servlet, que
 * MockMvc no realiza.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = WebGoat.class)
@TestPropertySource(
    locations = {
      "classpath:/application-webgoat.properties",
      "classpath:/application-webgoat-test.properties"
    })
class AdminEndpointNegativeSecurityTest {

  @MockitoBean private Language language;
  @MockitoBean private ClientRegistrationRepository clientRegistrationRepository;

  @Autowired private WebApplicationContext wac;

  @LocalServerPort private int port;

  private MockMvc mockMvc;
  private MockHttpSession adminSession;
  private MockHttpSession userSession;

  @BeforeEach
  void setUp() {
    when(language.getLocale()).thenReturn(Locale.getDefault());
    // Construye MockMvc CON la cadena real de filtros de Spring Security para que las pruebas
    // ejerzan la autenticación (entry point, sesión) y la autorización (401/403) exactamente como
    // por red, en vez de apoyarse en un contexto de seguridad preinyectado.
    this.mockMvc =
        MockMvcBuilders.webAppContextSetup(this.wac)
            .apply(SecurityMockMvcConfigurers.springSecurity())
            .build();
    this.adminSession = login("webgoat-admin", "webgoat");
    this.userSession = login("webgoat-user", "webgoat");
  }

  private String baseUrl() {
    return "http://localhost:" + port + "/WebGoat";
  }

  /** Realiza un form login real mediante {@code POST /login} y devuelve la sesión autenticada. */
  private MockHttpSession login(String username, String password) {
    MockHttpSession session = new MockHttpSession();
    try {
      mockMvc
          .perform(
              post("/login")
                  .session(session)
                  .param("username", username)
                  .param("password", password))
          .andExpect(status().is3xxRedirection());
    } catch (Exception e) {
      throw new IllegalStateException("Login failed for user: " + username, e);
    }
    return session;
  }

  /**
   * Autorización: un usuario normal que está autenticado pero carece de la autoridad {@code
   * WEBGOAT_ADMIN} debe recibir prohibido (403) y no ver ningún dato de usuarios.
   */
  @Test
  void authorization_regularUserMustNotAccessAdminEndpoint() throws Exception {
    mockMvc
        .perform(
            get("/service/admin/users")
                .session(userSession)
                .header("x-requested-with", "XMLHttpRequest")
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isForbidden())
        .andExpect(content().string(not(containsString("webgoat-admin"))));
  }

  /**
   * Autenticación: sin una sesión válida la petición es anónima y debe rechazarse: 401 para las
   * llamadas AJAX (vía {@code AjaxAuthenticationEntryPoint}) y un redirecionamiento 302 a {@code
   * /login} para las llamadas de navegador.
   */
  @Test
  void authentication_anonymousRequestMustNotBeAuthenticated() throws Exception {
    // Llamada AJAX sin sesión: 401.
    mockMvc
        .perform(
            get("/service/admin/users")
                .header("x-requested-with", "XMLHttpRequest")
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isUnauthorized());

    // Llamada de navegador sin sesión: redirecionamiento 302 a la página de login.
    mockMvc
        .perform(get("/service/admin/users"))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/login"));
  }

  /**
   * Validación de entradas: los payloads de inyección (inyección SQL y XSS) en la variable de ruta
   * {@code {username}} no deben ejecutarse ni reflejarse: el endpoint responde 404 para ellos,
   * mientras que un usuario válido sigue resolviéndose (el control no debe sobrebloquear).
   */
  @Test
  void inputValidation_injectionPayloadsInUsernameMustBeRejectedAndNotReflected()
      throws Exception {
    // Payload de inyección SQL: no debe ejecutarse como SQL (sin "usuario encontrado") ni
    // reflejarse.
    String sqli = "webgoat-admin' OR 1=1 --";
    mockMvc
        .perform(
            get("/service/admin/users/{username}", sqli)
                .session(adminSession)
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isNotFound())
        .andExpect(content().string(not(containsString("OR 1=1"))));

    // Payload de XSS: no debe reflejarse en el cuerpo de la respuesta.
    String xss = "<script>alert(1)</script>";
    mockMvc
        .perform(
            get("/service/admin/users/{username}", xss)
                .session(adminSession)
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isNotFound())
        .andExpect(content().string(not(containsString("<script>"))));

    // Sanidad del control: un usuario válido debe seguir resolviéndose (sin sobrebloquear).
    mockMvc
        .perform(
            get("/service/admin/users/{username}", "webgoat-admin")
                .session(adminSession)
                .accept(MediaType.APPLICATION_JSON))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.username").value("webgoat-admin"));
  }

  /**
   * Manejo de errores: un método HTTP no soportado en el endpoint produce un 405 a través del
   * error controller de Spring Boot. El cuerpo de error debe ser controlado: estado correcto y
   * mensaje genérico, pero sin stack trace ni nombres de clases internas.
   *
   * <p>Corre contra el servidor embebido real porque el error dispatch del servlet (y por tanto el
   * cuerpo JSON del error controller) no ocurre dentro de MockMvc.
   */
  @Test
  void errorHandling_errorResponsesMustNotLeakStackTrace() {
    RestTemplate rt = new RestTemplate(new SimpleClientHttpRequestFactory());

    // 1) Iniciar sesión como admin por HTTP real y capturar la cookie JSESSIONID.
    HttpHeaders loginHeaders = new HttpHeaders();
    loginHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("username", "webgoat-admin");
    form.add("password", "webgoat");
    ResponseEntity<String> loginResp =
        rt.exchange(
            baseUrl() + "/login", HttpMethod.POST, new HttpEntity<>(form, loginHeaders), String.class);
    assertEquals(HttpStatus.FOUND, loginResp.getStatusCode(), "Login must redirect on success");
    String setCookie = loginResp.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
    assertNotNull(setCookie, "Expected a JSESSIONID cookie after login");
    String cookie = setCookie.split(";")[0];

    // 2) Provocar un 405 (método no soportado) en el endpoint protegido con la sesión de admin.
    // RestTemplate expone los 4xx como HttpClientErrorException; la excepción lleva el cuerpo de
    // error.
    HttpHeaders headers = new HttpHeaders();
    headers.setAccept(List.of(MediaType.APPLICATION_JSON));
    headers.set("x-requested-with", "XMLHttpRequest");
    headers.set(HttpHeaders.COOKIE, cookie);
    String body;
    try {
      rt.exchange(
          baseUrl() + "/service/admin/users",
          HttpMethod.DELETE,
          new HttpEntity<>(headers),
          String.class);
      body = null; // Sin excepción: la petición no falló (resultado inesperado).
    } catch (HttpClientErrorException ex) {
      assertEquals(HttpStatus.METHOD_NOT_ALLOWED, ex.getStatusCode());
      body = ex.getResponseBodyAsString();
    }
    assertNotNull(body, "Expected a 4xx error body for the unsupported-method request");
    // El cuerpo de error debe ser controlado: sin stack trace, sin nombres de clases internas.
    assertFalse(body.contains("\"trace\""), "Error response leaks a stack trace: " + body);
    assertFalse(
        body.contains("org.springframework"),
        "Error response leaks internal class names: " + body);
  }
}
