# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** Israel Gallego Martínez
- **Repositorio:** https://github.com/igallego9-stack/reportaudit-lab
- **Sistema operativo y versión de Python usados:** Ubuntu 24.04 (WSL2), Python 3.12

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | `buscar_reportes_cliente` | 41-42 | Inyección SQL: concatena `nombre_cliente` en `query` | `request.args cliente` en `app/servicio.py:41` | `cursor execute(query)` en `app/reporte_auditoria.py:42` |
| 2 | `convertir_a_pdf` | 50-51 | Inyección de comandos: concatena `nombre_archivo` y usa `os.system` | `request.args archivo` en `app/servicio.py:53` | `os.system(comando)` en `app/reporte_auditoria.py:51` |
| 3 | `cargar_configuracion` | 33 | Deserialización YAML insegura: `yaml.load` con `Loader=yaml.Loader` | archivo `app/config.yaml` vía `RUTA_CONFIG` en `app/servicio.py:22` | `yaml.load(f, Loader=yaml.Loader)` en `app/reporte_auditoria.py:33` |
| 4 | `hash_password_legacy` | 57 | Hash débil MD5 sin sal para contraseñas | parámetro `password` | `hashlib.md5(password.encode()).hexdigest()` en `app/reporte_auditoria.py:57` |
| 5 | constantes | 21-22 | Secretos en código: `NOTIFICATION_API_KEY` y `SMTP_PASSWORD` en claro | propio código | `print` en `notificar_cliente:62` que loguea la clave / envío SMTP |

**Impacto en el negocio:** para cada sospecha, explica en una frase qué
consecuencia tendría para ReportAudit y sus clientes si fuera real (qué datos,
qué sistema o qué credencial quedarían expuestos).

H1 expone todos los reportes de todos los clientes.
H2 permite ejecución remota en el servidor.
H3 permite ejecución de código vía YAML malicioso.
H4 expone contraseñas por cracking rápido.
H5/H6 compromete notificaciones y correo (hay que rotarlas).

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ manual | pendiente captura IDE | pendiente captura Connected | ✓ SonarCloud (taint servicio.py->execute, ver Overview) | ✓ CodeQL `py/sql-injection` #2 fixed | ✗ Semgrep p/python no lo marca en este repo (`Passed`) | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ manual | pendiente captura IDE | pendiente captura Connected | ✓ SonarCloud (ver Overview) | ✓ CodeQL `py/command-line-injection` #3 fixed | ✗ Semgrep (`Passed` con os.system) | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ manual | ✓ IDE (regla yaml) | ✓ Connected | ✓ SonarCloud | ✗ CodeQL (no hay alerta yaml entre las 4 fixed) | ✓ Semgrep `avoid-pyyaml-load` (Failed H.3 capturado) | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ manual | ✓ IDE | ✓ Connected | ✓ SonarCloud | ✓ CodeQL `py/weak-sensitive-data-hashing` #4 fixed | ✓ Semgrep `insecure-hash-algorithm-md5` + `md5-used-as-password` (guía H.2; tras fix Passed) | n/a |
| H5 Clave de API escrita en el código | ✓ manual | ✓ IDE (secreto) | ✓ Connected | ✓ SonarCloud hotspot/secreto (ver Overview) | ✓ CodeQL `py/clear-text-logging-sensitive-data` #1 fixed | ✗ Semgrep p/secrets no la marcó (solo 3 findings H.2) | 0 tras fix (env var), pendiente captura secret |
| H6 Contraseña SMTP escrita en el código | ✓ manual | ✓ IDE (secreto) | ✓ Connected | ✓ SonarCloud hotspot (ver Overview) | ✗ CodeQL (solo 1 alerta logging #1) | ✗ Semgrep | 0 tras fix (env var) |

**Conclusión de la matriz**: ninguna lo detecta todo (CodeQL 4/6 sin yaml/H6, Semgrep solo H3/H4, Trivy solo SCA/secretos). Hay que combinar SAST+SCA+secretos: defensa en profundidad.

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | 2 (`flask`, `pyyaml`) |
| Componentes Python en el SBOM | 8 (`blinker 1.9.0, click 8.5.0, flask 3.1.3, itsdangerous 2.2.0, jinja2 3.1.6, markupsafe 3.0.4, pyyaml 6.0.3, werkzeug 3.1.9`) |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen | 4 `github-action` (`checkout v7, codeql init/analyze v4, sonarqube v8`) de `.github/workflows/cadena-suministro.yml` |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) | `CycloneDX 1.6` (`sbom.cyclonedx.json`) |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
| pyjwt | 2.9.0 | espuria (lockfile roto) | GHSA-w6j9-cwv2-h6wq Critical +13 | Critical | 2.14.0 | No aplica: no usa JWT | Eliminar (PR #19) |
| werkzeug | 3.0.6 | transitiva (`# via flask`) | GHSA-29vq-49wr-vm6x | Medium | 3.1.9 | Si: sirve HTTP Flask | Actualizar a 3.1.9 (PR #19) |
| jinja2 | 3.1.4 | transitiva (`# via flask`) | GHSA-q2x7-8rv6-6q7h | Medium | 3.1.5 | No explotable: usa `jsonify` (`app/servicio.py:43-46`), ver VEX; se actualiza a 3.1.6 | Actualizar + VEX |

**Comparación con Dependabot** (Parte H): ¿las alertas coinciden con Grype? Explica
cualquier diferencia.

**Documento VEX:** copia `plantillas/reportaudit.openvex.json` a
`docs/evidencias/`, rellénalo, enlázalo aquí y resume en una frase la
justificación.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | 1 blocking en prueba H.3 (`avoid-pyyaml-load`) | 0 (`Passed` en codigo corregido) |  |
| Alertas abiertas de CodeQL (Security → Code scanning) |  |  |
| Vulnerabilidades en SonarQube Cloud (rama main) |  |  |
| Security Hotspots por revisar en SonarQube Cloud |  |  |
| Vulnerabilidades de Grype sobre el SBOM | 23 (1 Critical, 4 High, 16 Medium, 2 Low) en `grype-antes.txt` | 0 en `grype-despues.txt` tras PR #24 (flask 3.1.3) |  |
| Alertas abiertas de Dependabot | 1 Low inicial (flask) + actions checkout v7 y sonar v8 | 0 (todas fusionadas: #22, #23, #24) |  |

---

## Preguntas de comprobación (Sección 7 de la guía)

1.
2.
3.
4.
5.
6.
7.
8.
9.
10.
11.
12.

## Backlog del laboratorio (Issues)

| Issue | Título | PR o evidencia de cierre |
|---|---|---|
| #3 | Adopt an international pull request template | PR #16 (abierto, checks verde, pendiente aprobacion) |
| #4 | Run SAST (SonarQube Cloud and CodeQL) on every pull request | |
| #5 | Block insecure commits with a Semgrep pre-commit hook | PR #17 (abierto, pendiente aprobacion) |
| #6 | Enable Dependabot alerts and security updates | PR #18 + Dependabot #22 (checkout v7), #23 (sonar v8), #24 (flask 3.1.3). CLOSED |
| #7 | Remediate the findings of the security audit | |
| #8 | Upgrade the vulnerable dependencies | PR #19 (jinja2/werkzeug, 23->1) + Dependabot #24 (flask 3.1.3, 1->0). CLOSED |
| #9 | Publish the audit log and the before/after evidence | |
| #10 | Detect ReportAudit credentials in the whole Git history | |
| #11 | Make SCA and secret scanning required checks on main | |
| #12 | Publish a security policy and a private vulnerability reporting channel | |
| #13 | Release v1.0.0 with an SBOM and signed provenance | |
| #14 | Measure supply-chain maturity with OpenSSF Scorecard | |
| #15 | Build the CRA evidence index | |
