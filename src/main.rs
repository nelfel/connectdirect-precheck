#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod report;
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::os::windows::process::CommandExt;
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Check {
    pub phase: String,
    pub name: String,
    pub state: String,
    pub detail: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ResultRow {
    pub server: String,
    pub computer: String,
    pub environment: String,
    pub started: String,
    pub finished: String,
    pub checks: Vec<Check>,
}
impl ResultRow {
    pub fn status(&self) -> &'static str {
        if self.checks.iter().any(|c| c.state == "FAIL") {
            "NO APTO"
        } else if self.checks.is_empty()
            || self
                .checks
                .iter()
                .any(|c| !matches!(c.state.as_str(), "OK" | "WARN" | "INFO"))
        {
            "INCOMPLETO"
        } else if self.checks.iter().any(|c| c.state == "WARN") {
            "CON OBSERVACIONES"
        } else {
            "APTO"
        }
    }
    fn error(req: &Request, detail: String, state: &str) -> Self {
        Self {
            server: req.server.clone(),
            computer: String::new(),
            environment: req.environment.clone(),
            started: String::new(),
            finished: String::new(),
            checks: vec![Check {
                phase: "Ejecucion".into(),
                name: "Consulta".into(),
                state: state.into(),
                detail,
            }],
        }
    }
}
#[derive(Clone, Serialize)]
struct Request {
    server: String,
    local: bool,
    environment: String,
    app_folder: String,
    min_system_gb: u32,
    min_install_gb: u32,
    min_temp_gb: u32,
    backup_margin_gb: u32,
    ports: Vec<u16>,
}
impl Default for Request {
    fn default() -> Self {
        Self {
            server: "localhost".into(),
            local: true,
            environment: "DESA".into(),
            app_folder: std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.display().to_string()))
                .unwrap_or_default(),
            min_system_gb: 10,
            min_install_gb: 5,
            min_temp_gb: 3,
            backup_margin_gb: 2,
            ports: vec![1363, 1364, 1365],
        }
    }
}
fn servers(input: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for name in input.split_whitespace() {
        if name.len() > 253
            || !name.split('.').all(|part| {
                !part.is_empty()
                    && part.len() <= 63
                    && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                    && part.as_bytes()[0].is_ascii_alphanumeric()
                    && part.as_bytes()[part.len() - 1].is_ascii_alphanumeric()
            })
            || name.parse::<std::net::IpAddr>().is_ok()
        {
            return Err(format!(
                "Servidor invalido: {name}. Usa nombres DNS, no IP (autenticacion Kerberos)."
            ));
        }
        if !names.iter().any(|n: &String| n.eq_ignore_ascii_case(name)) {
            names.push(name.to_owned());
        }
    }
    if names.is_empty() {
        return Err("Ingresa al menos un servidor.".into());
    }
    Ok(names)
}
fn ps_command(script: &str) -> Command {
    let path =
        PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut c = Command::new(path);
    c.env_remove("PSModulePath")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .creation_flags(0x08000000);
    c
}
fn execute(req: &Request, timeout: u64, cancel: &AtomicBool) -> Result<ResultRow, String> {
    let mut child = ps_command(include_str!("precheck.ps1"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    // Drain both pipes while running so a verbose result cannot deadlock the worker.
    let read_pipe = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).map(|_| bytes)
        })
    };
    let out = read_pipe(Box::new(stdout));
    let err = read_pipe(Box::new(stderr));
    let input = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    if let Err(e) = child.stdin.take().unwrap().write_all(&input) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e.to_string());
    }
    let start = Instant::now();
    let mut interrupted = None;
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(e) => {
                interrupted = Some(e.to_string());
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
        if cancel.load(Ordering::Relaxed) || start.elapsed() >= Duration::from_secs(timeout) {
            interrupted = Some(if cancel.load(Ordering::Relaxed) {
                "Consulta cancelada".to_string()
            } else {
                format!("Tiempo maximo de {timeout}s agotado; validacion incompleta")
            });
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let output = out
        .join()
        .map_err(|_| "Fallo leyendo salida")?
        .map_err(|e| e.to_string())?;
    let errors = err
        .join()
        .map_err(|_| "Fallo leyendo errores")?
        .map_err(|e| e.to_string())?;
    if let Some(message) = interrupted {
        return Err(message);
    }
    if !exit.is_some_and(|e| e.success()) {
        return Err(format!(
            "PowerShell fallo: {}",
            String::from_utf8_lossy(&errors)
        ));
    }
    let result: ResultRow = serde_json::from_slice(&output).map_err(|e| {
        format!(
            "Respuesta no valida: {e}; {}",
            String::from_utf8_lossy(&errors)
        )
    })?;
    if result.server != req.server || result.environment != req.environment {
        return Err("La respuesta no coincide con el servidor/ambiente solicitado".into());
    }
    Ok(result)
}
fn open_path(path: &std::path::Path) -> Result<(), String> {
    let script="$ErrorActionPreference='Stop'; [Console]::InputEncoding=New-Object Text.UTF8Encoding($false); $p=[Console]::In.ReadToEnd() | ConvertFrom-Json; Invoke-Item -LiteralPath $p";
    let mut child = ps_command(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            serde_json::to_string(&path.display().to_string())
                .unwrap()
                .as_bytes(),
        )
        .map_err(|e| e.to_string())?;
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}
fn reports_root() -> PathBuf {
    std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("ConnectDirectPrecheck.exe"))
        .with_file_name("Reportes")
}
enum Event {
    Row(ResultRow),
    Saved,
    Error(String),
    Done,
}
struct App {
    request: Request,
    servers: String,
    ports: String,
    parallel: usize,
    timeout: u64,
    rows: Vec<ResultRow>,
    receiver: Option<mpsc::Receiver<Event>>,
    cancel: Arc<AtomicBool>,
    output: Option<PathBuf>,
    message: String,
    filter: String,
    selected: Option<usize>,
    total: usize,
}
impl Default for App {
    fn default() -> Self {
        Self {
            request: Request::default(),
            servers: String::new(),
            ports: "1363,1364,1365".into(),
            parallel: 4,
            timeout: 180,
            rows: vec![],
            receiver: None,
            cancel: Arc::new(AtomicBool::new(false)),
            output: None,
            message: "Selecciona el ambiente y los servidores. El precheck detecta las rutas automáticamente.".into(),
            filter: String::new(),
            selected: None,
            total: 0,
        }
    }
}
impl App {
    fn start(&mut self) -> Result<(), String> {
        let names = if self.request.local {
            vec!["localhost".into()]
        } else {
            servers(&self.servers)?
        };
        let ports: Result<Vec<u16>, _> = self
            .ports
            .split(',')
            .map(|p| p.trim().parse::<u16>())
            .collect();
        let ports = ports.map_err(|_| "Puertos invalidos: usa numeros separados por comas")?;
        if ports.is_empty() || ports.contains(&0) {
            return Err("Los puertos deben estar entre 1 y 65535".into());
        }
        self.request.ports = ports;
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let folder = reports_root().join(format!("{id}"));
        std::fs::create_dir_all(&folder)
            .map_err(|e| format!("No se pueden crear reportes: {e}"))?;
        let mut reqs = Vec::new();
        for name in names {
            let mut req = self.request.clone();
            req.server = name;
            reqs.push(req);
        }
        let mut initial = Vec::new();
        for req in &reqs {
            initial.push(ResultRow::error(
                req,
                "En cola; todavia no validado".into(),
                "PENDIENTE",
            ));
        }
        report::save(&folder, &initial).map_err(|e| e.to_string())?;
        std::fs::write(
            folder.join("configuracion.json"),
            serde_json::to_vec_pretty(&reqs).unwrap(),
        )
        .map_err(|e| e.to_string())?;
        self.total = reqs.len();
        self.rows.clear();
        self.selected = None;
        self.output = Some(folder.clone());
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let timeout = self.timeout;
        let parallel = self.parallel;
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        self.message = "Validando...".into();
        std::thread::spawn(move || {
            let reqs = Arc::new(reqs);
            let index = Arc::new(AtomicUsize::new(0));
            let (result_tx, result_rx) = mpsc::channel();
            let mut handles = Vec::new();
            for _ in 0..parallel.min(reqs.len()) {
                let reqs = reqs.clone();
                let index = index.clone();
                let tx = result_tx.clone();
                let cancel = cancel.clone();
                handles.push(std::thread::spawn(move || loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = index.fetch_add(1, Ordering::Relaxed);
                    let Some(req) = reqs.get(i) else {
                        break;
                    };
                    let row = execute(req, timeout, &cancel)
                        .unwrap_or_else(|e| ResultRow::error(req, e, "ERROR"));
                    if tx.send((i, row)).is_err() {
                        break;
                    }
                }));
            }
            drop(result_tx);
            let mut snapshot = initial;
            let mut completed = vec![false; reqs.len()];
            let mut save_failed = false;
            for (i, row) in result_rx {
                completed[i] = true;
                snapshot[i] = row.clone();
                let _ = tx.send(Event::Row(row));
                if let Err(e) = report::save(&folder, &snapshot) {
                    cancel.store(true, Ordering::Relaxed);
                    save_failed = true;
                    let _ = tx.send(Event::Error(format!(
                        "Error guardando reportes: {e}. Lote detenido."
                    )));
                }
            }
            for h in handles {
                if h.join().is_err() {
                    let _ = tx.send(Event::Error(
                        "Un trabajador fallo; revisar servidores incompletos".into(),
                    ));
                }
            }
            for (i, req) in reqs.iter().enumerate() {
                if !completed[i] {
                    let row =
                        ResultRow::error(req, "No iniciado: lote detenido".into(), "CANCELADO");
                    snapshot[i] = row.clone();
                    let _ = tx.send(Event::Row(row));
                }
            }
            match report::save(&folder, &snapshot) {
                Ok(()) if !save_failed => {
                    let _ = tx.send(Event::Saved);
                }
                Ok(()) => {}
                Err(e) => {
                    let _ = tx.send(Event::Error(format!(
                        "No se pudo guardar el reporte final: {e}"
                    )));
                }
            }
            let _ = tx.send(Event::Done);
        });
        Ok(())
    }
}
fn status_color(status: &str) -> egui::Color32 {
    match status {
        "APTO" | "OK" => egui::Color32::from_rgb(26, 125, 89),
        "NO APTO" | "FAIL" => egui::Color32::from_rgb(190, 48, 53),
        "INFO" => egui::Color32::from_rgb(61, 103, 140),
        _ => egui::Color32::from_rgb(170, 105, 15),
    }
}
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.receiver.is_some() && ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.cancel.store(true, Ordering::Relaxed);
            self.message =
                "Deteniendo consultas y guardando resultados; podrás cerrar al terminar.".into();
        }
        let events: Vec<_> = self
            .receiver
            .as_ref()
            .map(|r| r.try_iter().collect())
            .unwrap_or_default();
        for event in events {
            match event {Event::Row(r)=>self.rows.push(r),Event::Saved=>self.message="Reportes guardados. Revisa observaciones y validaciones incompletas antes del parche.".into(),Event::Error(e)=>self.message=e,Event::Done=>self.receiver=None}
        }
        if self.receiver.is_some() {
            ctx.request_repaint_after(Duration::from_millis(150));
        }
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(10.0);
            ui.heading("Connect:Direct  /  Precheck");
            ui.label("Validación masiva de prerrequisitos de parchado · Solo lectura");
            ui.add_space(8.0);
        });
        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
            ui.label(&self.message);
            if let Some(path) = &self.output {
                ui.label(format!("Reportes: {}", path.display()));
            }
        });
        egui::SidePanel::left("config").default_width(355.0).resizable(true).show(ctx,|ui|{
            egui::ScrollArea::vertical().show(ui,|ui|{
                ui.add_enabled_ui(self.receiver.is_none(),|ui|{
                    ui.heading("Preparar validación");
                    ui.radio_value(&mut self.request.local,true,"Esta computadora (sin WinRM)");
                    ui.radio_value(&mut self.request.local,false,"Lista de servidores (WinRM / Kerberos)");
                    if !self.request.local {
                        ui.label("Servidores DNS, uno por línea");ui.add(egui::TextEdit::multiline(&mut self.servers).desired_rows(5).desired_width(f32::INFINITY));
                        if ui.button("Cargar lista TXT…").clicked() {if let Some(path)=rfd::FileDialog::new().add_filter("Lista de servidores",&["txt"]).pick_file() {match std::fs::read_to_string(path) {Ok(s)=>self.servers=s.trim_start_matches('\u{feff}').to_string(),Err(e)=>self.message=e.to_string()}}}
                        ui.small("Usa la cuenta de tu sesión. Requiere WinRM configurado y permisos en los destinos.");
                    }
                    ui.separator();
                    ui.horizontal(|ui|{ui.label("Ambiente");egui::ComboBox::from_id_salt("env").selected_text(&self.request.environment).show_ui(ui,|ui|{for env in ["DESA","CERT","PROD"] {ui.selectable_value(&mut self.request.environment,env.into(),env);}});});
                    ui.add_space(8.0);
                    ui.label("Detección automática");
                    ui.small("Instalaciones y versiones · Servicios · Cuenta AP3W · Fix disponible · Disco, TEMP y backup · Permisos");
                    ui.small("C: ≥ 10 GB · Instalación ≥ 5 GB · TEMP ≥ 3 GB · Backup: tamaño + 2 GB");
                    ui.collapsing("Ajustes avanzados",|ui|{
                        ui.label("Puertos TCP");ui.text_edit_singleline(&mut self.ports);
                        for (label,value) in [("C: mínimo GB",&mut self.request.min_system_gb),("Instalación mínimo GB",&mut self.request.min_install_gb),("TEMP mínimo GB",&mut self.request.min_temp_gb),("Margen backup GB",&mut self.request.backup_margin_gb)] {ui.horizontal(|ui|{ui.label(label);ui.add(egui::DragValue::new(value).range(1..=10000));});}
                    ui.horizontal(|ui|{ui.label("Simultáneos");ui.add(egui::DragValue::new(&mut self.parallel).range(1..=16));ui.label("Tiempo máx. (s)");ui.add(egui::DragValue::new(&mut self.timeout).range(15..=3600));});
                    });
                    ui.add_space(10.0);
                    if ui.add_sized([ui.available_width(),36.0],egui::Button::new("Validar precheck")).clicked() {if let Err(e)=self.start() {self.message=e;}}
                });
                if self.receiver.is_some() && ui.button("Detener consultas").clicked() {self.cancel.store(true,Ordering::Relaxed);self.message="Deteniendo; los servidores pendientes quedarán incompletos.".into();}
                ui.separator();ui.heading("Reportes");
                if let Some(root)=self.output.clone() {
                    ui.horizontal(|ui|{for (label,name) in [("Abrir HTML","resultado.html"),("Abrir CSV","resultado.csv")] {if ui.button(label).clicked() {if let Err(e)=open_path(&root.join(name)) {self.message=e;}}}});
                    if ui.button("Abrir carpeta").clicked() {if let Err(e)=open_path(&root) {self.message=e;}}
                    if ui.button("Copiar ruta").clicked() {ui.ctx().copy_text(root.display().to_string());}
                }
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Resultados");
                ui.label(format!("{} / {} servidores", self.rows.len(), self.total));
            });
            ui.horizontal_wrapped(|ui| {
                for status in ["APTO", "CON OBSERVACIONES", "NO APTO", "INCOMPLETO"] {
                    ui.colored_label(
                        status_color(status),
                        format!(
                            "{}  {}",
                            self.rows.iter().filter(|r| r.status() == status).count(),
                            status
                        ),
                    );
                }
            });
            if self.total > 0 {
                ui.add(
                    egui::ProgressBar::new(self.rows.len() as f32 / self.total as f32)
                        .show_percentage(),
                );
            }
            ui.horizontal(|ui| {
                ui.label("Buscar");
                ui.text_edit_singleline(&mut self.filter);
            });
            egui::ScrollArea::vertical()
                .id_salt("results")
                .max_height(240.0)
                .show(ui, |ui| {
                    egui::Grid::new("servers")
                        .striped(true)
                        .min_col_width(125.0)
                        .show(ui, |ui| {
                            ui.strong("Servidor");
                            ui.strong("Estado");
                            ui.strong("Comprobaciones");
                            ui.end_row();
                            for (i, row) in self.rows.iter().enumerate() {
                                if !format!("{} {}", row.server, row.status())
                                    .to_lowercase()
                                    .contains(&self.filter.to_lowercase())
                                {
                                    continue;
                                }
                                if ui
                                    .selectable_label(self.selected == Some(i), &row.server)
                                    .clicked()
                                {
                                    self.selected = Some(i);
                                }
                                ui.colored_label(status_color(row.status()), row.status());
                                let count = |state: &str| {
                                    row.checks.iter().filter(|c| c.state == state).count()
                                };
                                ui.label(format!(
                                    "{} OK · {} WARN · {} FAIL · {} ERROR",
                                    count("OK"),
                                    count("WARN"),
                                    count("FAIL"),
                                    count("ERROR")
                                ));
                                ui.end_row();
                            }
                        });
                });
            ui.separator();
            if let Some(row) = self.selected.and_then(|i| self.rows.get(i)) {
                ui.heading(format!("Detalle · {}", row.server));
                ui.label(format!(
                    "Equipo: {} · Ambiente: {} · {}",
                    row.computer, row.environment, row.finished
                ));
                egui::ScrollArea::vertical()
                    .id_salt("details")
                    .show(ui, |ui| {
                        for check in &row.checks {
                            ui.horizontal_wrapped(|ui| {
                                ui.colored_label(status_color(&check.state), &check.state);
                                ui.strong(format!("{} / {}", check.phase, check.name));
                            });
                            ui.label(&check.detail);
                            ui.add_space(7.0);
                        }
                    });
            } else {
                ui.label("Selecciona un servidor para revisar cada comprobación y su evidencia.");
            }
        });
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
fn main() -> eframe::Result {
    if std::env::args().any(|a| a == "--diagnose-local") {
        let req = Request::default();
        let result = execute(&req, 180, &AtomicBool::new(false))
            .unwrap_or_else(|e| ResultRow::error(&req, e, "ERROR"));
        let root = reports_root().join(format!(
            "diagnostico-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("Crear carpeta diagnostico");
        report::save(&root, &[result]).expect("Guardar diagnostico");
        return Ok(());
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 800.0])
            .with_min_inner_size([900.0, 620.0]),
        ..Default::default()
    };
    eframe::run_native(
        &format!("ConnectDirect Precheck {}", env!("CARGO_PKG_VERSION")),
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::light());
            Ok(Box::<App>::default())
        }),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timeout_stops_the_collector_without_a_result() {
        let error = execute(&Request::default(), 0, &AtomicBool::new(false)).unwrap_err();
        assert!(error.contains("Tiempo maximo"), "{error}");
    }
    #[test]
    fn rejects_injection_deduplicates_and_never_passes_missing_evidence() {
        assert_eq!(servers("SRV01 srv01\nsrv02.example.com").unwrap().len(), 2);
        for bad in ["", "srv;whoami", "-srv", "srv..com", "10.0.0.1", "srv_1"] {
            assert!(servers(bad).is_err(), "{bad}");
        }
        let mut row = ResultRow::error(&Request::default(), "test".into(), "ERROR");
        assert_eq!(row.status(), "INCOMPLETO");
        row.checks.clear();
        assert_eq!(row.status(), "INCOMPLETO");
        row.checks.push(Check {
            phase: "x".into(),
            name: "x".into(),
            state: "FAIL".into(),
            detail: String::new(),
        });
        assert_eq!(row.status(), "NO APTO");
        row.checks[0].state = "WARN".into();
        assert_eq!(row.status(), "CON OBSERVACIONES");
        row.checks[0].state = "OK".into();
        assert_eq!(row.status(), "APTO");
    }
}
