use std::collections::HashMap;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DockerPortOwner {
    pub(crate) container_id: String,
    pub(crate) container_name: String,
    pub(crate) image: String,
    pub(crate) container_port: u16,
    pub(crate) protocol: String,
}

pub(crate) type DockerPortMap = HashMap<u16, Vec<DockerPortOwner>>;

pub(crate) fn get_docker_port_map() -> DockerPortMap {
    let output = match Command::new("docker")
        .args([
            "ps",
            "--format",
            "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}",
        ])
        .output()
    {
        Ok(out) => out,
        Err(_) => return HashMap::new(),
    };

    if !output.status.success() {
        return HashMap::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ps_output(&stdout)
}

fn parse_ps_output(stdout: &str) -> DockerPortMap {
    let mut result: DockerPortMap = HashMap::new();

    for line in stdout.lines() {
        let mut fields = line.splitn(4, '\t');
        let (Some(container_id), Some(container_name), Some(image), Some(ports_raw)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };

        if ports_raw.trim().is_empty() {
            continue;
        }

        for segment in ports_raw.split(',') {
            let Some((host_port, container_port, protocol)) = parse_port_segment(segment) else {
                continue;
            };

            let owner = DockerPortOwner {
                container_id: container_id.to_string(),
                container_name: container_name.to_string(),
                image: image.to_string(),
                container_port,
                protocol,
            };

            let entry = result.entry(host_port).or_default();
            let exists = entry.iter().any(|existing| {
                existing.container_id == owner.container_id
                    && existing.container_port == owner.container_port
                    && existing.protocol == owner.protocol
            });
            if !exists {
                entry.push(owner);
            }
        }
    }

    result
}

fn parse_port_segment(segment: &str) -> Option<(u16, u16, String)> {
    let (host_side, container_side) = segment.trim().split_once("->")?;
    let host_port = parse_host_port(host_side.trim())?;
    let (container_port_raw, protocol_raw) = container_side.trim().split_once('/')?;
    let container_port = parse_first_port(container_port_raw.trim())?;
    let protocol = protocol_raw.trim().to_ascii_uppercase();
    Some((host_port, container_port, protocol))
}

fn parse_host_port(host_side: &str) -> Option<u16> {
    let raw = host_side.rsplit(':').next().unwrap_or(host_side);
    parse_first_port(raw.trim())
}

fn parse_first_port(raw: &str) -> Option<u16> {
    let first = raw.split('-').next()?.trim();
    first.parse::<u16>().ok()
}

/// Run a Docker action (stop or restart) on a container by name.
/// Returns a status message string.
pub(crate) fn run_docker_action(action: &str, container_name: &str) -> String {
    let output = match Command::new("docker")
        .args([action, container_name])
        .output()
    {
        Ok(out) => out,
        Err(e) => return format!("Failed to run docker {}: {}", action, e),
    };

    if output.status.success() {
        format!("docker {} {}: OK", action, container_name)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!(
            "docker {} {} failed: {}",
            action,
            container_name,
            stderr.trim()
        )
    }
}

/// Fetch the last few lines of logs from a Docker container.
pub(crate) fn run_docker_logs(container_name: &str) -> String {
    let output = match Command::new("docker")
        .args(["logs", "--tail", "20", container_name])
        .output()
    {
        Ok(out) => out,
        Err(e) => return format!("Failed to get logs: {}", e),
    };

    // Docker logs may write to stdout or stderr depending on the container
    let combined = if !output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stdout).to_string()
    } else {
        String::from_utf8_lossy(&output.stderr).to_string()
    };

    // Return last 5 lines as a preview
    let lines: Vec<&str> = combined.lines().collect();
    let start = lines.len().saturating_sub(5);
    lines[start..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_segment_ipv4() {
        let parsed = parse_port_segment("0.0.0.0:8080->80/tcp");
        assert_eq!(parsed, Some((8080, 80, "TCP".to_string())));
    }

    #[test]
    fn parse_port_segment_ipv6() {
        let parsed = parse_port_segment("[::]:8443->443/tcp");
        assert_eq!(parsed, Some((8443, 443, "TCP".to_string())));
    }

    #[test]
    fn parse_port_segment_range() {
        let parsed = parse_port_segment("0.0.0.0:49153-49155->8080-8082/tcp");
        assert_eq!(parsed, Some((49153, 8080, "TCP".to_string())));
    }

    #[test]
    fn parse_port_segment_unpublished_is_ignored() {
        let parsed = parse_port_segment("80/tcp");
        assert_eq!(parsed, None);
    }

    #[test]
    fn parse_ps_output_builds_map_and_deduplicates_ipv4_ipv6_entries() {
        let input = "\
abc123\tweb\tnginx:latest\t0.0.0.0:8080->80/tcp, :::8080->80/tcp
def456\tdb\tpostgres:16\t127.0.0.1:5432->5432/tcp
ghi789\tworker\tworker:latest\t
";
        let map = parse_ps_output(input);

        assert_eq!(map.len(), 2);

        let web = map.get(&8080).expect("expected 8080 mapping");
        assert_eq!(web.len(), 1);
        assert_eq!(web[0].container_name, "web");
        assert_eq!(web[0].container_port, 80);

        let db = map.get(&5432).expect("expected 5432 mapping");
        assert_eq!(db.len(), 1);
        assert_eq!(db[0].container_name, "db");
        assert_eq!(db[0].image, "postgres:16");
    }
}
