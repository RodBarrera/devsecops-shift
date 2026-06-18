# DevSecOps Shift-Left Pipeline Demo

Demostración práctica de **seguridad integrada en el pipeline de CI/CD** bajo un
enfoque *shift-left*: una aplicación web deliberadamente vulnerable y su versión
corregida, atravesando un pipeline que ejecuta **SAST, SCA, secret scanning y
DAST**, y que **bloquea el despliegue** cuando encuentra vulnerabilidades.

> El objetivo no es explotar la app, sino demostrar cómo se **detectan y corrigen**
> las vulnerabilidades *antes* de que lleguen a producción. La app vulnerable es un
> artefacto educativo y aislado, en la línea de DVWA u OWASP Juice Shop.

El gancho del proyecto es el contraste: el **mismo pipeline** se pone 🔴 **rojo**
sobre la rama `vulnerable` y 🟢 **verde** sobre la rama `secure`. Esa diferencia,
visible en un solo vistazo, es la materialización de *security by design*.

![Pipeline en rojo sobre la app vulnerable](docs/pipeline-fail.png)
![Pipeline en verde sobre la app corregida](docs/pipeline-pass.png)

> _Reemplaza estas capturas por las de tus ejecuciones reales de GitHub Actions._

## Concepto: shift-left

"Mover la seguridad a la izquierda" significa adelantar los controles a las etapas
tempranas del ciclo de vida del desarrollo (SDLC), en lugar de dejarlos para una
auditoría al final. Cada *commit* pasa por una batería de análisis automáticos; si
introduce una vulnerabilidad, el pipeline falla y el cambio no avanza. El costo de
corregir cae drásticamente cuando el problema se detecta en el *pull request* y no
en producción.

## Arquitectura

```
                    ┌─────────────────────────────────────────────┐
   git push  ──────▶│            GitHub Actions (CI/CD)            │
   / PR             │                                             │
                    │  1. Secret Scanning   →  Gitleaks           │
                    │  2. SAST              →  Bandit + Semgrep    │
                    │  3. SCA (deps)        →  pip-audit / Trivy   │
                    │  4. Build + run app   →  Docker              │
                    │  5. DAST              →  OWASP ZAP baseline  │
                    │                                             │
                    │  ── Gate: ¿hallazgos sobre el umbral? ──     │
                    │        sí → ❌ falla (no deploy)            │
                    │        no → ✅ pasa  → deploy permitido     │
                    └─────────────────────────────────────────────┘
                              ▲                        ▲
                    rama `vulnerable`           rama `secure`
                       (🔴 falla)                 (🟢 pasa)
```

## Estructura del proyecto

```
devsecops-shift-left-demo/
├── app/                      # Aplicación Flask
│   ├── app.py                # Rutas y lógica (vulns intencionales en `vulnerable`)
│   ├── db.py                 # Acceso a datos
│   ├── templates/            # Plantillas Jinja2
│   └── requirements.txt      # Dependencias (una con CVE en `vulnerable`)
├── tests/                    # Pruebas unitarias mínimas
├── .github/
│   └── workflows/
│       └── security.yml      # Pipeline de seguridad (el corazón del demo)
├── .gitleaks.toml            # Config de secret scanning
├── .semgrep.yml              # Reglas SAST (o ruleset OWASP por defecto)
├── zap/
│   └── rules.tsv             # Umbral de fallos del DAST (ZAP)
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## La aplicación vulnerable

Una pequeña app de notas/login en **Flask**, elegida por ser liviana y dejar las
vulnerabilidades a la vista sin ruido. La rama `vulnerable` incluye, a propósito,
fallas representativas del **OWASP Top 10 (2021)**; la rama `secure` las corrige
una a una.

## Mapeo: vulnerabilidad → OWASP → detección → corrección

| Vulnerabilidad intencional | OWASP Top 10 (2021) | Detectada por | Corrección en `secure` |
|---|---|---|---|
| Inyección SQL (query con concatenación) | A03 – Injection | Bandit (B608), Semgrep, ZAP | Consultas parametrizadas / ORM |
| XSS almacenado (template sin escapar) | A03 – Injection | Semgrep, ZAP (DAST) | Autoescape de Jinja2 + encoding de salida |
| Inyección de comandos (`shell=True`) | A03 – Injection | Bandit (B602/B605), Semgrep | `subprocess` con lista de args, sin shell |
| Contraseñas en texto plano / hash débil (MD5) | A02 – Cryptographic Failures | Bandit (B303), Semgrep | Hashing con bcrypt/argon2 |
| Secretos hardcodeados (API key en código) | A05 – Security Misconfiguration | Gitleaks, Bandit (B105/B106) | Variables de entorno / secrets manager |
| IDOR / control de acceso roto | A01 – Broken Access Control | ZAP (parcial), revisión manual | Verificación de propiedad y autorización |
| Dependencia con CVE conocido | A06 – Vulnerable & Outdated Components | pip-audit / Trivy (SCA) | Actualización de la versión fijada |

> **Detalle que suma valor en una entrevista:** el IDOR muestra a propósito los
> *límites* de las herramientas automáticas. El SAST no lo cazará bien porque es
> un fallo de lógica de autorización, no de patrón de código. Eso abre la
> conversación sobre por qué el shift-left **complementa** —pero no reemplaza— la
> revisión de diseño y el pentesting manual.

## El pipeline (GitHub Actions)

El workflow `security.yml` se dispara en cada `push` y `pull_request`, y encadena
las etapas en orden de costo creciente (lo barato y rápido primero):

1. **Secret Scanning — Gitleaks.** Detecta credenciales y llaves filtradas en el
   código y el historial. Falla si encuentra secretos.
2. **SAST — Bandit + Semgrep.** Análisis estático del código fuente. Bandit aporta
   la cobertura específica de Python; Semgrep agrega reglas de seguridad OWASP.
3. **SCA — pip-audit / Trivy.** Revisa las dependencias contra bases de CVE y
   reporta paquetes vulnerables u obsoletos.
4. **Build & run — Docker.** Construye la imagen y levanta la app para la fase
   dinámica.
5. **DAST — OWASP ZAP (baseline).** Escaneo dinámico contra la app corriendo, que
   detecta lo que solo se ve en ejecución (XSS reflejado, cabeceras inseguras).

**El gate.** Cada etapa devuelve un código de salida; si alguna supera el umbral
de severidad definido, el job falla y el pipeline se detiene. Ese fallo es,
literalmente, "el shift-left bloqueando el deploy". En `secure` todas las etapas
pasan y el deploy queda habilitado.

## Cómo ejecutarlo localmente

```bash
# Clonar y elegir la versión a inspeccionar
git clone https://github.com/<tu-usuario>/devsecops-shift-left-demo.git
cd devsecops-shift-left-demo

# Levantar la app (versión vulnerable o segura según la rama)
docker compose up --build
# App disponible en http://localhost:5000
```

Para reproducir los análisis del pipeline en tu máquina:

```bash
pip install bandit semgrep pip-audit
bandit -r app/
semgrep --config auto app/
pip-audit -r app/requirements.txt
```

## Decisiones de seguridad (writeup)

- **Aislamiento.** La app solo corre en local / en el runner efímero del CI; nunca
  se despliega públicamente. Su único propósito es ser analizada.
- **Defensa en profundidad en el pipeline.** Se combinan cuatro tipos de análisis
  (secretos, estático, dependencias y dinámico) porque ninguno cubre todo por sí
  solo; juntos cubren código, configuración, terceros y runtime.
- **Fallar de forma segura.** El pipeline está configurado para *bloquear* ante la
  duda (umbral conservador), no para advertir y dejar pasar.
- **Trazabilidad.** Cada etapa publica su reporte como artefacto del workflow, de
  modo que un hallazgo siempre tiene evidencia asociada.
- **Reproducibilidad.** Dependencias fijadas y entorno en Docker: cualquiera
  obtiene el mismo resultado.

## Roadmap

- [ ] Publicar los reportes de cada herramienta como artefactos descargables.
- [ ] Integrar el formato **SARIF** para que los hallazgos aparezcan en la pestaña
      *Security* de GitHub.
- [ ] Agregar firma de imágenes / SBOM (cadena de suministro).
- [ ] Escaneo de IaC (Dockerfile / Compose) con Trivy o Checkov.
- [ ] Tabla comparativa de hallazgos `vulnerable` vs `secure` generada
      automáticamente.

## Licencia

MIT — uso libre con atribución. Software con vulnerabilidades intencionales,
provisto únicamente con fines educativos.

---

Desarrollado por **Rod Barrera** · Ingeniero en Ciberseguridad.
