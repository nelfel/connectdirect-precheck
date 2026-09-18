use crate::ResultRow;
use std::{fs, io, path::Path};
fn html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn csv(s: &str) -> String {
    let safe = if s.trim_start().starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_owned()
    };
    format!("\"{}\"", safe.replace('"', "\"\""))
}
pub fn save(folder: &Path, rows: &[ResultRow]) -> io::Result<()> {
    let mut data=String::from("\u{feff}Servidor,Equipo,Ambiente,Veredicto,Inicio,Fin,Fase,Comprobacion,Estado,Detalle\r\n");
    let mut body = String::new();
    for row in rows {
        let class = match row.status() {
            "APTO" => "ok",
            "NO APTO" => "fail",
            _ => "warn",
        };
        body.push_str(&format!("<section><h2>{} <span class='{class}'>{}</span></h2><p>Equipo: {} · Ambiente: {} · Inicio: {} · Fin: {}</p><table><thead><tr><th>Fase</th><th>Comprobación</th><th>Estado</th><th>Evidencia</th></tr></thead><tbody>",html(&row.server),row.status(),html(&row.computer),html(&row.environment),html(&row.started),html(&row.finished)));
        for c in &row.checks {
            data.push_str(
                &[
                    &row.server,
                    &row.computer,
                    &row.environment,
                    row.status(),
                    &row.started,
                    &row.finished,
                    &c.phase,
                    &c.name,
                    &c.state,
                    &c.detail,
                ]
                .map(csv)
                .join(","),
            );
            data.push_str("\r\n");
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html(&c.phase),
                html(&c.name),
                html(&c.state),
                html(&c.detail)
            ));
        }
        body.push_str("</tbody></table></section>");
    }
    let summary = ["APTO", "CON OBSERVACIONES", "NO APTO", "INCOMPLETO"]
        .map(|s| {
            format!(
                "<b>{}</b> {}",
                rows.iter().filter(|r| r.status() == s).count(),
                s
            )
        })
        .join(" &nbsp; | &nbsp; ");
    let page = format!(
        r#"<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect:Direct · Precheck</title><style>body{{font:15px system-ui;background:#f3f6fa;color:#19334b;margin:32px}}section{{background:white;padding:20px;border-radius:12px;margin:20px 0}}table{{width:100%;border-collapse:collapse}}td,th{{text-align:left;padding:10px;border-bottom:1px solid #dae3ec;vertical-align:top;overflow-wrap:anywhere}}td:last-child{{width:58%}}span{{font-size:14px}}.ok{{color:#19774f}}.fail{{color:#b42d35}}.warn{{color:#906012}}input{{padding:10px;width:300px}}@media print{{input{{display:none}}body{{margin:0}}}}</style><h1>Connect:Direct / Precheck</h1><p>Solo lectura · Versión {}</p><p>{summary}</p><p>CON OBSERVACIONES requiere revisión. INCOMPLETO no autoriza parchado. NO APTO puede incluir errores adicionales de consulta. Los requisitos del fix IBM y los permisos efectivos se revisan manualmente.</p><input aria-label="Buscar" placeholder="Buscar servidor, estado o comprobación" oninput="document.querySelectorAll('section').forEach(s=>s.hidden=!s.textContent.toLowerCase().includes(this.value.toLowerCase()))">{body}</html>"#,
        env!("CARGO_PKG_VERSION")
    );
    let json = serde_json::to_vec_pretty(rows)?;
    for (name, bytes) in [
        ("resultado.csv", data.as_bytes()),
        ("resultado.html", page.as_bytes()),
        ("resultado.json", json.as_slice()),
    ] {
        let tmp = folder.join(format!("{name}.tmp"));
        fs::write(&tmp, bytes)?;
        fs::rename(tmp, folder.join(name))?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escapes_reports_and_replaces_snapshots() {
        assert_eq!(csv("=1+1"), "\"'=1+1\"");
        assert_eq!(html("<script>"), "&lt;script&gt;");
        let path = std::env::temp_dir().join(format!("cd-precheck-test-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        save(&path, &[]).unwrap();
        save(&path, &[]).unwrap();
        assert!(fs::read_to_string(path.join("resultado.html"))
            .unwrap()
            .contains("Precheck"));
        for name in ["resultado.html", "resultado.csv", "resultado.json"] {
            fs::remove_file(path.join(name)).unwrap();
        }
        fs::remove_dir(path).unwrap();
    }
}
