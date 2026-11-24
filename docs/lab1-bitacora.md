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

**Documento VEX:** [`docs/evidencias/reportaudit.openvex.json`](evidencias/reportaudit.openvex.json)
(GHSA-ffc3-869f-jxw9, `pkg:pypi/pyjwt@2.9.0`, `not_affected`,
`vulnerable_code_not_in_execute_path`). Justificación: PyJWT no es dependencia de
ReportAudit (`requirements.in` solo declara flask y pyyaml) y ningún módulo de
`app/` importa `jwt` (`servicio.py:12-20`, `reporte_auditoria.py:14-20`).

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

1. **Windows, Ubuntu y GitHub.** En Windows viven VS Code (solo la interfaz), el navegador y el PDF de la guía. En Ubuntu (WSL2) viven el proyecto (`~/reportaudit-lab`), Python, Git, `gh`, las herramientas de `tools/` y la terminal donde se ejecuta todo. En GitHub viven el repositorio remoto, el pipeline, los Issues y PRs, la protección de main y las Releases. Se trabaja en Ubuntu porque las herramientas (Syft, Grype, Trivy, Gitleaks) son binarios de Linux y porque el sistema de archivos de Linux es mucho más rápido que `/mnt/c`.
2. **Directa y transitiva.** Directa es la que declaro yo en `requirements.in` (`flask`, `pyyaml`). Transitiva es la que llega porque otra la necesita: `werkzeug` y `jinja2` entran por `flask` (`# via flask` en `requirements.txt`). En el SBOM hay 8 paquetes Python frente a 2 directas: es el efecto iceberg. Muchas vulnerabilidades estaban en transitivas (werkzeug, jinja2).
3. **Source y sink.** Source es el punto por donde entra un dato que controla el usuario; sink, la operación peligrosa a la que llega. Ejemplo: `request.args.get("cliente")` en `app/servicio.py` (source) llega a `buscar_reportes_cliente`, que construía la consulta SQL y la pasaba a `cursor.execute` en `app/reporte_auditoria.py` (sink).
4. **o'brien_ltd.** La comilla simple del nombre cerraba la cadena del SQL concatenado y dejaba el resto de la consulta mal formada, y la consulta fallaba. Que un dato de entrada altere la estructura de la sentencia demuestra que se interpretaba como código SQL, es decir, una inyección.
5. **Semgrep.** El hook actúa en local, antes del commit, y bloquea el código inseguro antes de que salga de mi equipo; SonarQube Cloud y CodeQL actúan después, en el PR. El hook solo no basta porque se puede saltar (`--no-verify`) o no instalar, y no analiza el repositorio remoto ni las dependencias.
6. **Herramientas distintas.** No es un error: cada una tiene reglas, modelos y alcance distintos. En mi matriz, CodeQL detectó 4 de 6, Semgrep solo H3 y H4, y Trivy se centra en SCA y secretos con formato conocido. Ninguna lo detecta todo, por eso se combinan (defensa en profundidad).
7. **PR de código y PR de Dependabot.** Son problemas distintos: el PR de código corrige el código propio (SAST), no las versiones de las librerías; y el de Dependabot sube versiones (SCA) pero no toca mi código. Cada alerta se cierra donde vive su causa.
8. **Borrar y corregir.** Borrar el secreto del código no lo quita del historial de Git, ni de clones ni forks. Corregir de verdad es rotar la credencial en el servicio real (la antigua deja de valer) y sacarla a una variable de entorno. Gitleaks sigue encontrando las antiguas en el commit de importación.
9. **VEX.** Ignorar una alerta no deja constancia; un VEX documenta quién, cuándo y con qué argumento se decidió. Mi VEX declara que GHSA-ffc3-869f-jxw9 (PyJWT 2.9.0) está `not_affected` porque PyJWT no es dependencia de ReportAudit ni ningún módulo de `app/` importa `jwt`.
10. **Instalador de herramientas.** Descarga una versión fijada y compara la huella SHA-256 con la publicada antes de instalar. No garantiza que la publicación oficial no esté comprometida: en el caso Trivy de 2026 la huella publicada también era la del binario malicioso. Por eso se fijan versiones revisadas y, en entornos exigentes, se verifica la firma.
11. **Gitleaks.** El código actual no tiene credenciales (están en variables de entorno), pero el commit de importación `9e332fc` sigue en el historial. Lo que cierra el riesgo es rotar las credenciales (Parte M); borrar la línea no basta. La baseline en `.gitleaksignore` registra esos dos hallazgos concretos sin desactivar la regla.
12. **Ratchet.** pip-audit no se exigió en la Parte G porque había dependencias vulnerables y habría bloqueado todos los PRs. Se corrigió primero (Parte M) y se hizo obligatorio después (Parte P), de modo que ya no se puede retroceder: el PR #30, con jinja2 3.1.4, fue rechazado por el check.
13. **Dependabot y pip-audit.** Dependabot avisa y propone un PR, pero no impide fusionar nada; `SCA - pip-audit` es un check obligatorio de main y bloquea cualquier PR que introduzca una dependencia vulnerable.

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

---

## Bloque final -- Publicar y demostrar (Partes O-T)

### O. Secretos en el historial (Gitleaks)

| Escaneo | Comando | N.º de hallazgos | Commit(s) donde aparecen |
|---|---|---|---|
| Código actual, reglas por defecto | `gitleaks dir app` | 0 | — |
| Historial, reglas por defecto | `gitleaks git .` | 1 (`generic-api-key`, `app/reporte_auditoria.py:21`; solo NOTIFICATION_API_KEY) | 9e332fc (importación, Parte A) |
| Historial, con regla propia | `gitleaks git . -c .gitleaks.toml` | 2 (`reportaudit-hardcoded-credential`, líneas 21 y 22) | 9e332fc |
| Historial, tras .gitleaksignore | `gitleaks git . -c .gitleaks.toml` | 0 (`no leaks found`; `dir app` también 0) | — |

**¿Por qué el código actual está limpio y el historial no?** En la Parte M las credenciales pasaron a
variables de entorno, así que los archivos de hoy no las contienen. Pero el commit de importación (9e332fc)
sigue en GitHub, en cada clon y en cada fork, y `git log -p` lo muestra. Las reglas por defecto solo
reconocieron una de las dos (el formato no es el de ningún proveedor); la regla propia encontró las dos.

**¿Qué medida cierra el riesgo?** Rotar las credenciales en el servicio real (Parte M): lo que está en el
historial deja de servir. Borrar la línea del código no lo cierra, porque el historial conserva el valor.

**`.gitleaksignore` frente a desactivar la regla:** cada línea apunta a un hallazgo concreto (commit, archivo,
regla y línea) con su motivo, y un secreto nuevo, aunque sea en el mismo archivo, sigue haciendo fallar el
análisis. Desactivar la regla dejaría de vigilar todo. Los valores nunca aparecen en la evidencia (`--redact`).

### P. Puertas obligatorias en main

| Check | ¿Exigido en main? | Resultado en el PR de prueba (test/puerta-sca) |
|---|---|---|
| SAST - SonarQube Cloud | Sí | Verde (el código no cambió) |
| SAST - CodeQL | Sí | Verde |
| SCA - pip-audit | Sí (añadido en P.4) | **Rojo**: jinja2 3.1.4 con PYSEC-2026-1471, -1472 y -1475 (corregidas en 3.1.5/3.1.6). Evidencia: `docs/evidencias/pip-audit-puerta-sca.txt` |
| Secretos - Gitleaks | Sí (añadido en P.4) | Verde |

Notas: el PR de prueba fue el draft #30, cerrado sin fusionar y con la rama borrada. Un primer intento (#29,
werkzeug 3.0.1) también dio rojo, pero por un conflicto de resolución con Flask 3.1.3 y no por una
vulnerabilidad, así que lo repetí con jinja2. Secret scanning y push protection ya estaban en *Enabled*.
Los PRs #26, #27 y #28 se fusionaron con `gh pr merge --admin` por no haber revisor disponible.

**Dependabot frente a pip-audit:** Dependabot avisa y propone un PR, pero no impide fusionar; pip-audit como
check obligatorio hace que un PR con una dependencia vulnerable no pueda entrar en main.
**¿Por qué no se exigió desde la Parte G?** Porque el código tenía dependencias vulnerables hasta la Parte M:
exigirlo antes habría bloqueado todos los PRs. Es un trinquete: primero se limpia y luego se prohíbe retroceder.

### Q. Divulgación coordinada (simulacro)

- Informe recibido de (usuario de GitHub):
- Identificador del borrador de aviso (GHSA-...):
- Severidad y vector CVSS:
- CWE:
- Versiones afectadas / versión corregida:

### R. Versión 1.0.0 verificable

| Comprobación | Comando | Resultado |
|---|---|---|
| Huellas SHA-256 | `sha256sum -c SHA256SUMS` | OK para `reportaudit-1.0.0.tar.gz` y `reportaudit-sbom.cdx.json` |
| Procedencia (SLSA) | `gh attestation verify reportaudit-1.0.0.tar.gz --repo igallego9-stack/reportaudit-lab` | Correcta (exit 0): predicado `slsa.dev/provenance/v1`, workflow `publicar-version.yml@refs/tags/v1.0.0` |
| SBOM atestado | `gh attestation verify ... --predicate-type https://cyclonedx.org/bom` | Correcta (exit 0): predicado `cyclonedx.org/bom`, mismo workflow y etiqueta |
| Archivo alterado | `gh attestation verify alterado.tar.gz --repo ...` | **Falla** (exit 1, HTTP 404: no hay atestación para esa huella). Huella `9a9030b4…` frente a `863eafaf…` del original |

Notas: el `gh` 2.45.0 de Ubuntu no incluye `attestation`; verifiqué con gh 2.105.0 instalado en `~/gh-verif`
(SHA-256 comprobado), fuera del repositorio. Con `--format json` se ve el detalle del certificado.

**¿Qué ataque detecta cada comprobación?** Las huellas, una descarga corrupta o incompleta; no detectan que
alguien cambie archivo y `SHA256SUMS` a la vez. La procedencia detecta un archivo no construido por mi workflow
desde esta etiqueta, aunque el atacante cambie las huellas. El SBOM atestado demuestra que ese inventario
describe exactamente ese paquete. Ninguna detecta un workflow comprometido que firme código malicioso, ni que
el código en sí sea inseguro (eso lo cubren los checks de cada PR y la revisión).

### S. Madurez (OpenSSF Scorecard)

| Check | Puntuación (0-10) | Qué la explica |
|---|---|---|
| Puntuación global | 6.6 | Calculada el 2026-11-24 sobre `main` tras fusionar el PR #33 |
| Pinned-Dependencies | 0 | Las acciones de los workflows usan etiquetas (`@v7`), no hashes de commit. Es el reto S.3 |
| Maintained | 0 | El repositorio tiene menos de 90 días: refleja que es nuevo, no que sea inseguro |
| Code-Review | 4 | Solo 6 de 13 changesets aprobados por otra persona: los PRs #26-#28, #31-#33 se fusionaron con `--admin` por no haber revisor |
| License | 0 | No hay archivo de licencia en el repositorio |
| Contributors | 0 | Sin contribuidores de organizaciones distintas (un solo autor) |

Otros: CII-Best-Practices 0 y Fuzzing 0 (no se persiguen); Branch-Protection sin datos (-1, el token no puede
leer las reglas clásicas, como anticipa la guía). Signed-Releases 8: reconoce 1 artefacto firmado de la Release.
Con 10: Security-Policy, Dependency-Update-Tool, Token-Permissions, SAST, Vulnerabilities, Dangerous-Workflow,
Binary-Artifacts y CI-Tests.

**Punto de control:** el más útil para elegir una dependencia es Vulnerabilities (y Signed-Releases/Token-
Permissions por la cadena de suministro); el más engañoso sin contexto es Maintained, que penaliza a un proyecto
nuevo, y Code-Review, que aquí baja por una circunstancia del laboratorio y no por el código.

### T. Expediente de evidencias

Ver `docs/cra/expediente-evidencias.md`.

Compara el expediente con tu respuesta B5 de la Práctica 2: ¿qué evidencia imaginaste que ahora
existe de verdad, y cuál sigue sin existir?
