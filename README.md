# ConnectDirect Precheck 0.2.0

Herramienta independiente para ejecutar masivamente el precheck de IBM Connect:Direct Windows. Rust proporciona la ventana, concurrencia y reportes; PowerShell incorporado consulta cada servidor. No instala parches ni modifica configuración.

## Uso

1. Abre `ConnectDirectPrecheck.exe`.
2. Selecciona esta computadora o pega/carga un TXT UTF-8 con servidores DNS.
3. Selecciona DESA, CERT o PROD y pulsa **Validar precheck**.
4. Selecciona un resultado para ver evidencias y abre el reporte HTML/CSV.

**No hay que escribir rutas, dominio, instalador ni versión.** El motor descubre cada instalación mediante servicios y registro, obtiene versión y unidad y evalúa todas las instalaciones detectadas. La cuenta AP3WDES/AP3WCER/AP3WPRO se resuelve automáticamente en Windows con el ambiente seleccionado.

## Qué valida

Las reglas proceden del script entregado por el usuario, atribuido a V4L3NC14 (2026):

- Sesión administrativa, PowerShell, ExecutionPolicy, reinicio pendiente y VC++.
- Instalaciones, versiones, prohibición de Connect:Direct en C:, servicios y sus cuentas.
- Puertos TCP 1363/1364/1365; su escucha no acredita apertura del firewall.
- Cuenta AP3W y pertenencia directa a Administradores/Power Users por SID. Los grupos anidados requieren revisión si no hay pertenencia directa.
- Fix disponible y versión superior a la instalada.
- C: mínimo 10 GB; volumen de cada instalación: 5 GB; TEMP: 3 GB. Falta de espacio en C:/instalación produce FAIL; TEMP produce WARN como en el script original.
- Backup: tamaño de cada instalación más 2 GB en la raíz de su volumen. No crea el backup. No sigue enlaces/junctions; informa una estimación incompleta si existen o si no puede leer archivos.
- ACL de instalación y raíz del volumen: escritura declarada para Administradores/SYSTEM, sin denegaciones de escritura detectadas. Este criterio del script original no demuestra permisos efectivos de AP3W; el detalle lo indica expresamente.

Los umbrales y puertos se pueden ajustar en **Ajustes avanzados**. No se suman consumos de instalación, temporales y backups simultáneos: se aplican las comprobaciones individuales del script base.

## Búsqueda automática del fix

En cada disco fijo del destino consulta `stage`, `staging`, `install`, `installers`, `instaladores`, `software`, `patches`, `parches`, `packages`, `temp` e `IBM`. También consulta las instalaciones detectadas, sus carpetas padre y TEMP. En modo local añade la carpeta del ejecutable, equivalente al directorio del script original.

Busca hasta tres niveles y 400 carpetas, sin seguir enlaces. **No escanea exhaustivamente todo el servidor.** El reporte registra el alcance, candidatos y carpetas inaccesibles. Si no encuentra un paquete, informa FAIL en esa comprobación y continúa validando espacio, cuentas y servicios; no pide una ruta ni inventa una versión. Puede haber un fix fuera del alcance consultado.

Selecciona automáticamente la mayor versión de la misma rama major/minor/build que la instalada, y exige que sea superior. Si obtiene la versión solo del nombre, o no confirma identidad en metadatos, deja WARN. Una versión igual o inferior produce FAIL. Esto no certifica aplicabilidad ni procedencia: se contrasta con el paquete IBM aprobado.

## Conexión y resultados

Windows x64 con Windows PowerShell 5.1. Remoto mediante WinRM/Kerberos con la cuenta de la sesión Windows/PAM. Requiere nombres DNS, dominio, conectividad y permisos adecuados previamente configurados. No habilita WinRM, no cambia TrustedHosts, no guarda contraseñas ni deja agentes en los destinos.

Por defecto ejecuta cuatro consultas simultáneas y 180 segundos máximos por servidor. Detener cancela consultas activas y marca los pendientes como incompletos. Un cierre normal durante el lote detiene y guarda antes de permitir cerrar. Un cierre forzado conserva el último reporte guardado.

Los reportes HTML/CSV/JSON y configuración se guardan en `Reportes\<ejecución>` junto al ejecutable. Un error de guardado detiene las nuevas consultas.

- **NO APTO:** algún FAIL; revisar también errores adicionales.
- **INCOMPLETO:** error, cancelación o falta de resultado, sin un FAIL ya conocido.
- **CON OBSERVACIONES:** hay WARN, sin FAIL/ERROR.
- **APTO:** comprobaciones sin FAIL/ERROR/WARN, dentro del alcance documentado.

## Compilar y probar

```powershell
cargo test --locked
powershell.exe -NoProfile -File tests\collector-tests.ps1
cargo build --release --locked
.\target\release\ConnectDirectPrecheck.exe --diagnose-local
```

El diagnóstico local consulta esta computadora y genera reportes. Las pruebas remotas y con Connect:Direct real requieren el entorno de laboratorio del usuario.
