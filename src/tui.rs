use std::collections::HashSet;
use std::io;
use std::time::{Duration, Instant};

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table, TableState,
};

use crate::docker::{
    DockerPortMap, DockerPortOwner, get_docker_port_map, run_docker_action, run_docker_logs,
};
#[cfg(target_os = "linux")]
use crate::linux::get_port_infos;
#[cfg(target_os = "macos")]
use crate::macos::get_port_infos;
#[cfg(target_os = "windows")]
use crate::windows::get_port_infos;

use crate::{
    PortInfo, StyleConfig, chrono_free_time, format_addr, format_bytes, format_uptime,
    kill_process, short_container_id, synthesize_docker_entries, truncate_cmd, wrap_cmd,
};

// ── Sort types ───────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
enum SortColumn {
    Port,
    Proto,
    Address,
    Pid,
    User,
    Process,
    Uptime,
    Mem,
    Command,
}

impl SortColumn {
    fn next(self) -> Self {
        match self {
            Self::Port => Self::Proto,
            Self::Proto => Self::Pid,
            Self::Pid => Self::Address,
            Self::Address => Self::User,
            Self::User => Self::Process,
            Self::Process => Self::Uptime,
            Self::Uptime => Self::Mem,
            Self::Mem => Self::Command,
            Self::Command => Self::Port,
        }
    }

    fn prev(self) -> Self {
        match self {
            Self::Port => Self::Command,
            Self::Proto => Self::Port,
            Self::Pid => Self::Proto,
            Self::Address => Self::Pid,
            Self::User => Self::Address,
            Self::Process => Self::User,
            Self::Uptime => Self::Process,
            Self::Mem => Self::Uptime,
            Self::Command => Self::Mem,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Port => "PORT",
            Self::Proto => "PROTO",
            Self::Pid => "PID",
            Self::Address => "ADDRESS",
            Self::User => "USER",
            Self::Process => "PROCESS",
            Self::Uptime => "UPTIME",
            Self::Mem => "MEM",
            Self::Command => "COMMAND",
        }
    }

    fn from_index(i: usize) -> Option<Self> {
        match i {
            0 => Some(Self::Port),
            1 => Some(Self::Proto),
            2 => Some(Self::Pid),
            3 => Some(Self::Address),
            4 => Some(Self::User),
            5 => Some(Self::Process),
            6 => Some(Self::Uptime),
            7 => Some(Self::Mem),
            8 => Some(Self::Command),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum SortDirection {
    Asc,
    Desc,
}

impl SortDirection {
    fn toggle(self) -> Self {
        match self {
            Self::Asc => Self::Desc,
            Self::Desc => Self::Asc,
        }
    }

    fn indicator(self) -> &'static str {
        match self {
            Self::Asc => " \u{25b2}",
            Self::Desc => " \u{25bc}",
        }
    }
}

// ── Theme ────────────────────────────────────────────────────────────

struct TuiTheme {
    border: Style,
    title: Style,
    header_active: Style,
    header_inactive: Style,
    highlight_bg: Style,
    highlight_symbol: &'static str,
    footer_key: Style,
    footer_text: Style,
    status_ok: Style,
    filter_accent: Style,
    kill_border: Style,
}

impl TuiTheme {
    fn default_btop() -> Self {
        Self {
            border: Style::default().fg(Color::Rgb(60, 70, 85)),
            title: Style::default()
                .fg(Color::Rgb(80, 200, 200))
                .add_modifier(Modifier::BOLD),
            header_active: Style::default()
                .fg(Color::Rgb(100, 200, 200))
                .add_modifier(Modifier::BOLD),
            header_inactive: Style::default()
                .fg(Color::Rgb(90, 90, 90))
                .add_modifier(Modifier::BOLD),
            highlight_bg: Style::default()
                .bg(Color::Rgb(30, 40, 55))
                .add_modifier(Modifier::BOLD),
            highlight_symbol: "\u{2502} ",
            footer_key: Style::default().fg(Color::Rgb(100, 200, 200)),
            footer_text: Style::default().fg(Color::Rgb(130, 135, 140)),
            status_ok: Style::default().fg(Color::Rgb(120, 200, 130)),
            filter_accent: Style::default().fg(Color::Rgb(180, 130, 200)),
            kill_border: Style::default().fg(Color::Rgb(200, 80, 80)),
        }
    }

    fn no_color() -> Self {
        Self {
            border: Style::default(),
            title: Style::default().add_modifier(Modifier::BOLD),
            header_active: Style::default().add_modifier(Modifier::BOLD),
            header_inactive: Style::default().add_modifier(Modifier::BOLD),
            highlight_bg: Style::default().add_modifier(Modifier::BOLD),
            highlight_symbol: "\u{2502} ",
            footer_key: Style::default().add_modifier(Modifier::BOLD),
            footer_text: Style::default().add_modifier(Modifier::DIM),
            status_ok: Style::default(),
            filter_accent: Style::default().add_modifier(Modifier::BOLD),
            kill_border: Style::default(),
        }
    }
}

// ── App state ────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum AppMode {
    Table,
    Detail,
    FilterInput,
}

struct KillPopup {
    pid: u32,
    process_name: String,
    port: u16,
    force: bool,
}

struct DockerPopup {
    container_name: String,
    port: u16,
    selected: usize, // 0=Stop, 1=Restart, 2=Logs
}

enum Popup {
    Kill(KillPopup),
    Docker(DockerPopup),
}

pub struct App {
    ports: Vec<PortInfo>,
    docker_enabled: bool,
    docker_map: DockerPortMap,
    table_state: TableState,
    mode: AppMode,
    show_all: bool,
    filter_text: String,
    popup: Option<Popup>,
    target: Option<String>,
    styles: StyleConfig,
    theme: TuiTheme,
    wide: bool,
    default_force: bool,
    should_quit: bool,
    last_refresh: Instant,
    detail_index: usize,
    status_message: Option<(String, Instant)>,
    sort_column: SortColumn,
    sort_direction: SortDirection,
}

impl App {
    fn new(
        target: Option<&str>,
        show_all: bool,
        wide: bool,
        force: bool,
        no_color: bool,
        docker_enabled: bool,
        styles: StyleConfig,
    ) -> Self {
        let theme = if no_color {
            TuiTheme::no_color()
        } else {
            TuiTheme::default_btop()
        };
        let mut app = Self {
            ports: Vec::new(),
            docker_enabled,
            docker_map: DockerPortMap::default(),
            table_state: TableState::default(),
            mode: AppMode::Table,
            show_all,
            filter_text: String::new(),
            popup: None,
            target: target.map(|s| s.to_string()),
            styles,
            theme,
            wide,
            default_force: force,
            should_quit: false,
            last_refresh: Instant::now() - Duration::from_secs(2), // force immediate refresh
            detail_index: 0,
            status_message: None,
            sort_column: SortColumn::Port,
            sort_direction: SortDirection::Asc,
        };
        app.refresh_data();
        if !app.sorted_ports().is_empty() {
            app.table_state.select(Some(0));
        }
        app
    }

    fn refresh_data(&mut self) {
        self.ports = get_port_infos(!self.show_all);
        self.docker_map = if self.docker_enabled {
            get_docker_port_map()
        } else {
            DockerPortMap::default()
        };
        if self.docker_enabled {
            let synthetic = synthesize_docker_entries(&self.ports, &self.docker_map);
            self.ports.extend(synthetic);
        }
        self.last_refresh = Instant::now();

        // Clamp selection
        let count = self.sorted_ports().len();
        if count == 0 {
            self.table_state.select(None);
        } else if let Some(sel) = self.table_state.selected() {
            if sel >= count {
                self.table_state.select(Some(count - 1));
            }
        } else {
            self.table_state.select(Some(0));
        }
    }

    fn docker_owners_for_port(&self, port: u16) -> Option<&[DockerPortOwner]> {
        self.docker_map.get(&port).map(|owners| owners.as_slice())
    }

    fn docker_search_match(&self, port: u16, needle: &str) -> bool {
        self.docker_owners_for_port(port).is_some_and(|owners| {
            owners.iter().any(|owner| {
                owner.container_name.to_lowercase().contains(needle)
                    || owner.image.to_lowercase().contains(needle)
                    || owner.container_id.to_lowercase().contains(needle)
            })
        })
    }

    fn docker_tag_for_port(&self, port: u16) -> Option<String> {
        let owners = self.docker_owners_for_port(port)?;
        let first = owners.first()?;
        if owners.len() == 1 {
            Some(first.container_name.clone())
        } else {
            Some(format!("{}+{}", first.container_name, owners.len() - 1))
        }
    }

    fn filtered_ports(&self) -> Vec<&PortInfo> {
        let mut result: Vec<&PortInfo> = self.ports.iter().collect();

        // Apply CLI target filter (process name search)
        if let Some(ref target) = self.target {
            if let Ok(port) = target.parse::<u16>() {
                result.retain(|i| i.port == port);
            } else {
                let t = target.to_lowercase();
                result.retain(|i| {
                    i.process_name.to_lowercase().contains(&t)
                        || i.command.to_lowercase().contains(&t)
                        || (self.docker_enabled && self.docker_search_match(i.port, &t))
                });
            }
        }

        // Apply interactive filter
        if !self.filter_text.is_empty() {
            let f = self.filter_text.to_lowercase();
            result.retain(|i| {
                i.port.to_string().contains(&f)
                    || i.protocol.to_lowercase().contains(&f)
                    || i.pid.to_string().contains(&f)
                    || i.local_addr.to_string().contains(&f)
                    || i.process_name.to_lowercase().contains(&f)
                    || i.command.to_lowercase().contains(&f)
                    || i.user.to_lowercase().contains(&f)
                    || (self.docker_enabled && self.docker_search_match(i.port, &f))
            });
        }

        result
    }

    fn sorted_ports(&self) -> Vec<&PortInfo> {
        let mut result = self.filtered_ports();
        let dir = self.sort_direction;
        result.sort_by(|a, b| {
            let cmp = match self.sort_column {
                SortColumn::Port => a.port.cmp(&b.port),
                SortColumn::Proto => a.protocol.to_lowercase().cmp(&b.protocol.to_lowercase()),
                SortColumn::Pid => a.pid.cmp(&b.pid),
                SortColumn::User => a.user.to_lowercase().cmp(&b.user.to_lowercase()),
                SortColumn::Process => a
                    .process_name
                    .to_lowercase()
                    .cmp(&b.process_name.to_lowercase()),
                SortColumn::Uptime => {
                    // Earlier start_time = longer uptime = should sort first in Asc
                    // None sorts last
                    match (a.start_time, b.start_time) {
                        (Some(sa), Some(sb)) => sa.cmp(&sb),
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (None, None) => std::cmp::Ordering::Equal,
                    }
                }
                SortColumn::Mem => a.memory_bytes.cmp(&b.memory_bytes),
                SortColumn::Command => a.command.to_lowercase().cmp(&b.command.to_lowercase()),
                SortColumn::Address => a.local_addr.cmp(&b.local_addr),
            };
            if dir == SortDirection::Desc {
                cmp.reverse()
            } else {
                cmp
            }
        });
        result
    }

    fn selected_port(&self) -> Option<&PortInfo> {
        let ports = self.sorted_ports();
        self.table_state
            .selected()
            .and_then(|i| ports.get(i).copied())
    }

    fn select_next(&mut self) {
        let count = self.sorted_ports().len();
        if count == 0 {
            return;
        }
        let i = self.table_state.selected().unwrap_or(0);
        self.table_state.select(Some((i + 1).min(count - 1)));
    }

    fn select_prev(&mut self) {
        let count = self.sorted_ports().len();
        if count == 0 {
            return;
        }
        let i = self.table_state.selected().unwrap_or(0);
        self.table_state.select(Some(i.saturating_sub(1)));
    }

    fn select_first(&mut self) {
        if !self.sorted_ports().is_empty() {
            self.table_state.select(Some(0));
        }
    }

    fn select_last(&mut self) {
        let count = self.sorted_ports().len();
        if count > 0 {
            self.table_state.select(Some(count - 1));
        }
    }
}

// ── Rendering ────────────────────────────────────────────────────────

fn build_title_line(app: &App) -> Line<'_> {
    let visible_ports = app.sorted_ports();
    let port_count = visible_ports.len();
    let mut spans = vec![
        Span::styled(" portview", app.theme.title),
        Span::styled("  ", app.theme.footer_text),
        Span::styled(
            format!(
                "{} port{}",
                port_count,
                if port_count == 1 { "" } else { "s" }
            ),
            app.theme.title,
        ),
        Span::raw(" "),
    ];

    if app.show_all {
        spans.push(Span::styled(
            "(all) ",
            Style::default().fg(Color::Rgb(220, 180, 80)),
        ));
    }

    if !app.filter_text.is_empty() {
        spans.push(Span::styled(
            format!("[filter: {}] ", app.filter_text),
            app.theme.filter_accent,
        ));
    }

    if let Some(ref target) = app.target {
        spans.push(Span::styled(
            format!("[target: {}] ", target),
            app.theme.footer_text,
        ));
    }

    if app.docker_enabled {
        let mapped_count = visible_ports
            .iter()
            .filter(|info| app.docker_map.contains_key(&info.port))
            .count();
        spans.push(Span::styled(
            format!("[docker: {} mapped] ", mapped_count),
            Style::default().fg(Color::Rgb(110, 190, 220)),
        ));
    }

    if let Some((ref msg, at)) = app.status_message {
        if at.elapsed() < Duration::from_secs(3) {
            spans.push(Span::styled(msg.clone(), app.theme.status_ok));
            spans.push(Span::raw(" "));
        }
    }

    Line::from(spans)
}

fn build_footer_line(app: &App) -> Line<'_> {
    let time = chrono_free_time();

    if app.mode == AppMode::FilterInput {
        Line::from(vec![
            Span::styled(" /", app.theme.filter_accent),
            Span::raw(&app.filter_text),
            Span::styled("\u{2588}", app.theme.filter_accent),
            Span::styled("  Enter", app.theme.footer_key),
            Span::styled(" apply  ", app.theme.footer_text),
            Span::styled("Esc", app.theme.footer_key),
            Span::styled(" cancel ", app.theme.footer_text),
        ])
    } else {
        let mut spans = vec![
            Span::styled(" j/k", app.theme.footer_key),
            Span::styled(" move  ", app.theme.footer_text),
            Span::styled("Enter", app.theme.footer_key),
            Span::styled(" inspect  ", app.theme.footer_text),
            Span::styled("d/D", app.theme.footer_key),
            Span::styled(" action  ", app.theme.footer_text),
            Span::styled("/", app.theme.footer_key),
            Span::styled(" filter  ", app.theme.footer_text),
            Span::styled("</>/r", app.theme.footer_key),
            Span::styled(" sort  ", app.theme.footer_text),
            Span::styled("a", app.theme.footer_key),
            Span::styled(" all  ", app.theme.footer_text),
            Span::styled("q", app.theme.footer_key),
            Span::styled(" quit  ", app.theme.footer_text),
        ];
        if app.docker_enabled {
            spans.push(Span::styled("docker", app.theme.footer_key));
            spans.push(Span::styled(" filterable  ", app.theme.footer_text));
        }
        spans.push(Span::styled(
            format!("Updated {} ", time),
            app.theme.footer_text,
        ));
        Line::from(spans)
    }
}

fn render(frame: &mut ratatui::Frame, app: &mut App) {
    let area = frame.area();

    // Clear entire frame to prevent popup artifacts
    frame.render_widget(Clear, area);

    let title_line = build_title_line(app);
    let footer_line = build_footer_line(app);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(app.theme.border)
        .title_top(title_line)
        .title_bottom(footer_line);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    match app.mode {
        AppMode::Table | AppMode::FilterInput => render_table(frame, app, inner),
        AppMode::Detail => render_detail(frame, app, inner),
    }

    // Popup overlay
    match &app.popup {
        Some(Popup::Kill(_)) => render_kill_popup(frame, app, area),
        Some(Popup::Docker(_)) => render_docker_popup(frame, app, area),
        None => {}
    }
}

fn render_table(frame: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let ports = app.sorted_ports();
    let wide = app.wide;

    let widths = [
        Constraint::Length(6),
        Constraint::Length(5),
        Constraint::Length(7),
        Constraint::Length(15),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Fill(1),
    ];

    // Compute cmd_width by replicating ratatui's Table layout: first split off the
    // highlight-symbol area, then lay out columns with spacing in the remainder.
    let hl_width = if app.table_state.selected().is_some() {
        app.theme.highlight_symbol.chars().count() as u16
    } else {
        0
    };
    let [_, columns_area] = Layout::horizontal([Constraint::Length(hl_width), Constraint::Fill(0)])
        .areas(Rect::new(0, 0, area.width, 1));
    let col_rects = Layout::horizontal(widths).spacing(1).split(columns_area);
    let cmd_width = (col_rects[8].width as usize).max(10);

    let columns = [
        SortColumn::Port,
        SortColumn::Proto,
        SortColumn::Pid,
        SortColumn::Address,
        SortColumn::User,
        SortColumn::Process,
        SortColumn::Uptime,
        SortColumn::Mem,
        SortColumn::Command,
    ];

    let header_cells: Vec<Cell> = columns
        .iter()
        .map(|col| {
            let is_active = *col == app.sort_column;
            let label = if is_active {
                format!("{}{}", col.label(), app.sort_direction.indicator())
            } else {
                col.label().to_string()
            };
            let style = if is_active {
                app.theme.header_active
            } else {
                app.theme.header_inactive
            };
            Cell::from(label).style(style)
        })
        .collect();
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = ports
        .iter()
        .map(|info| {
            let mut command_text = info.command.clone();
            if app.docker_enabled && info.pid != 0 {
                if let Some(tag) = app.docker_tag_for_port(info.port) {
                    command_text.push_str(&format!(" [ctr:{}]", tag));
                }
            }

            let cmd_lines = if wide {
                wrap_cmd(&command_text, cmd_width)
            } else {
                vec![truncate_cmd(&command_text, cmd_width)]
            };
            let row_height = cmd_lines.len().max(1) as u16;
            let cmd_text = Text::from(cmd_lines.into_iter().map(Line::from).collect::<Vec<_>>());
            let is_synthetic = info.pid == 0;
            let docker_blue = Style::default()
                .fg(Color::Rgb(110, 190, 220))
                .add_modifier(Modifier::BOLD);
            let has_docker =
                app.docker_enabled && !is_synthetic && app.docker_map.contains_key(&info.port);
            let process_style = if is_synthetic {
                docker_blue
            } else if has_docker {
                app.theme.status_ok.add_modifier(Modifier::BOLD)
            } else {
                app.styles.process
            };
            let process_text = if has_docker {
                format!("{}*", info.process_name)
            } else {
                info.process_name.clone()
            };
            let pid_str = if is_synthetic {
                "-".to_string()
            } else {
                info.pid.to_string()
            };

            let local_addr = info.local_addr.to_string();

            Row::new(vec![
                Cell::from(info.port.to_string()).style(app.styles.port),
                Cell::from(info.protocol.clone()).style(app.styles.proto),
                Cell::from(pid_str).style(app.styles.pid),
                Cell::from(local_addr).style(app.styles.local_addr),
                Cell::from(info.user.clone()).style(app.styles.user),
                Cell::from(process_text).style(process_style),
                Cell::from(Line::from(format_uptime(info.start_time)).alignment(Alignment::Right))
                    .style(app.styles.uptime),
                Cell::from(Line::from(format_bytes(info.memory_bytes)).alignment(Alignment::Right))
                    .style(app.styles.mem),
                Cell::from(cmd_text).style(app.styles.command),
            ])
            .height(row_height)
        })
        .collect();

    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(app.theme.highlight_bg)
        .highlight_symbol(app.theme.highlight_symbol);

    frame.render_stateful_widget(table, area, &mut app.table_state);
}

fn render_detail(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let ports = app.sorted_ports();
    let info = match ports.get(app.detail_index) {
        Some(i) => i,
        None => {
            let p =
                Paragraph::new("Port no longer available.").style(Style::default().fg(Color::Red));
            frame.render_widget(p, area);
            return;
        }
    };

    let bind_str = format!("{}:{}", format_addr(&info.local_addr), info.port);
    let uptime = format_uptime(info.start_time);
    let is_docker = info.pid == 0;
    let docker_blue = Style::default().fg(Color::Rgb(110, 190, 220));

    let mut title_spans = vec![
        Span::styled("Port ", app.theme.title),
        Span::styled(info.port.to_string(), app.theme.title),
        Span::styled(format!(" ({}) ", info.protocol), app.theme.footer_text),
        Span::styled("\u{2014} ", app.theme.footer_text),
        Span::styled(&info.process_name, app.theme.status_ok),
    ];
    if is_docker {
        title_spans.push(Span::styled(" [container]", docker_blue));
    } else {
        title_spans.push(Span::styled(
            format!(" (PID {})", info.pid),
            Style::default().fg(Color::Rgb(220, 180, 80)),
        ));
    }
    let title_line = Line::from(title_spans);

    let label_style = app.theme.footer_text;

    let rows: Vec<(&str, String)> = if is_docker {
        vec![
            ("Bind:", bind_str),
            ("Image:", info.command.clone()),
            ("State:", info.state.to_string()),
        ]
    } else {
        vec![
            ("Bind:", bind_str),
            ("Command:", info.command.clone()),
            ("User:", info.user.clone()),
            ("Started:", format!("{} ago", uptime)),
            ("Memory:", format_bytes(info.memory_bytes)),
            ("CPU time:", format!("{:.1}s", info.cpu_seconds)),
            ("Children:", info.children.to_string()),
            ("State:", info.state.to_string()),
        ]
    };

    let mut lines = vec![Line::default(), title_line, Line::default()];
    for (label, value) in &rows {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:<10}", label), label_style),
            Span::raw(value),
        ]));
    }

    if app.docker_enabled {
        lines.push(Line::default());
        let owners = app.docker_owners_for_port(info.port).unwrap_or(&[]);
        if owners.is_empty() {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{:<10}", "Docker:"), label_style),
                Span::raw("none"),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!("{:<10}", "Docker:"), label_style),
                Span::raw(format!("{} mapping(s)", owners.len())),
            ]));
            let mut seen = HashSet::new();
            for owner in owners {
                lines.push(Line::from(vec![
                    Span::raw("    - "),
                    Span::styled(owner.container_name.clone(), app.theme.status_ok),
                    Span::raw(format!(
                        " [{}] ({}) {} -> {}/{}",
                        owner.image,
                        short_container_id(&owner.container_id),
                        info.port,
                        owner.container_port,
                        owner.protocol
                    )),
                ]));
                if seen.insert(owner.container_name.clone()) {
                    lines.push(Line::from(vec![Span::raw(format!(
                        "      docker logs --tail 100 {}",
                        owner.container_name
                    ))]));
                    lines.push(Line::from(vec![Span::raw(format!(
                        "      docker restart {}",
                        owner.container_name
                    ))]));
                }
            }
        }
    }

    lines.push(Line::default());
    if is_docker {
        lines.push(Line::from(vec![
            Span::styled("  Esc", app.theme.footer_key),
            Span::styled(" back  ", app.theme.footer_text),
            Span::styled("d", app.theme.footer_key),
            Span::styled(" stop/restart/logs  ", app.theme.footer_text),
            Span::styled("q", app.theme.footer_key),
            Span::styled(" quit", app.theme.footer_text),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled("  Esc", app.theme.footer_key),
            Span::styled(" back  ", app.theme.footer_text),
            Span::styled("d", app.theme.footer_key),
            Span::styled(" kill  ", app.theme.footer_text),
            Span::styled("D", app.theme.footer_key),
            Span::styled(" force kill  ", app.theme.footer_text),
            Span::styled("q", app.theme.footer_key),
            Span::styled(" quit", app.theme.footer_text),
        ]));
    }

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, area);
}

fn render_kill_popup(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let popup = match &app.popup {
        Some(Popup::Kill(p)) => p,
        _ => return,
    };

    let signal = if popup.force { "SIGKILL" } else { "SIGTERM" };

    let text = vec![
        Line::default(),
        Line::from(vec![
            Span::raw("  Kill "),
            Span::styled(&popup.process_name, app.theme.status_ok),
            Span::raw(format!(" (PID {}) on port {}?", popup.pid, popup.port)),
        ]),
        Line::from(vec![Span::raw(format!("  Signal: {}", signal))]),
        Line::default(),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("y/Enter", app.theme.footer_key),
            Span::styled(" confirm   ", app.theme.footer_text),
            Span::styled("n/Esc", app.theme.footer_key),
            Span::styled(" cancel", app.theme.footer_text),
        ]),
        Line::default(),
    ];

    let popup_width = 50u16.min(area.width.saturating_sub(4));
    let popup_height = 6u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(app.theme.kill_border)
        .title(" Kill Process ")
        .title_alignment(Alignment::Center)
        .title_style(app.theme.kill_border.add_modifier(Modifier::BOLD));

    frame.render_widget(Clear, popup_area);
    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, popup_area);
}

fn render_docker_popup(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let popup = match &app.popup {
        Some(Popup::Docker(p)) => p,
        _ => return,
    };

    let actions = ["Stop", "Restart", "Logs"];
    let docker_blue = Style::default().fg(Color::Rgb(110, 190, 220));

    let mut lines = vec![
        Line::default(),
        Line::from(vec![
            Span::raw("  Container: "),
            Span::styled(&popup.container_name, app.theme.status_ok),
            Span::raw(format!(" (port {})", popup.port)),
        ]),
        Line::default(),
    ];

    for (i, action) in actions.iter().enumerate() {
        let marker = if i == popup.selected { "> " } else { "  " };
        let style = if i == popup.selected {
            docker_blue.add_modifier(Modifier::BOLD)
        } else {
            app.theme.footer_text
        };
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{}{}", marker, action), style),
        ]));
    }

    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled("j/k", app.theme.footer_key),
        Span::styled(" navigate  ", app.theme.footer_text),
        Span::styled("Enter", app.theme.footer_key),
        Span::styled(" confirm  ", app.theme.footer_text),
        Span::styled("Esc", app.theme.footer_key),
        Span::styled(" cancel", app.theme.footer_text),
    ]));
    lines.push(Line::default());

    let popup_width = 50u16.min(area.width.saturating_sub(4));
    let popup_height = 9u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(docker_blue)
        .title(" Docker Container ")
        .title_alignment(Alignment::Center)
        .title_style(docker_blue.add_modifier(Modifier::BOLD));

    frame.render_widget(Clear, popup_area);
    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, popup_area);
}

// ── Event handling ───────────────────────────────────────────────────

fn handle_key(app: &mut App, code: KeyCode, modifiers: KeyModifiers) {
    // Global: Ctrl+C always quits
    if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    // Popup takes priority
    match &app.popup {
        Some(Popup::Kill(_)) => {
            handle_kill_popup_key(app, code);
            return;
        }
        Some(Popup::Docker(_)) => {
            handle_docker_popup_key(app, code);
            return;
        }
        None => {}
    }

    match app.mode {
        AppMode::Table => handle_table_key(app, code),
        AppMode::Detail => handle_detail_key(app, code),
        AppMode::FilterInput => handle_filter_key(app, code),
    }
}

fn handle_table_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('j') | KeyCode::Down => app.select_next(),
        KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
        KeyCode::Char('g') | KeyCode::Home => app.select_first(),
        KeyCode::Char('G') | KeyCode::End => app.select_last(),
        KeyCode::Enter => {
            if let Some(idx) = app.table_state.selected() {
                app.detail_index = idx;
                app.mode = AppMode::Detail;
            }
        }
        KeyCode::Char('d') => {
            if let Some(info) = app.selected_port().cloned() {
                if info.pid == 0 {
                    app.popup = Some(Popup::Docker(DockerPopup {
                        container_name: info.process_name.clone(),
                        port: info.port,
                        selected: 0,
                    }));
                } else {
                    app.popup = Some(Popup::Kill(KillPopup {
                        pid: info.pid,
                        process_name: info.process_name.clone(),
                        port: info.port,
                        force: app.default_force,
                    }));
                }
            }
        }
        KeyCode::Char('D') => {
            if let Some(info) = app.selected_port().cloned() {
                if info.pid == 0 {
                    app.popup = Some(Popup::Docker(DockerPopup {
                        container_name: info.process_name.clone(),
                        port: info.port,
                        selected: 0,
                    }));
                } else {
                    app.popup = Some(Popup::Kill(KillPopup {
                        pid: info.pid,
                        process_name: info.process_name.clone(),
                        port: info.port,
                        force: true,
                    }));
                }
            }
        }
        KeyCode::Char('/') => {
            app.mode = AppMode::FilterInput;
            app.filter_text.clear();
        }
        KeyCode::Char('a') => {
            app.show_all = !app.show_all;
            app.refresh_data();
        }
        KeyCode::Char('<') => {
            app.sort_column = app.sort_column.prev();
        }
        KeyCode::Char('>') => {
            app.sort_column = app.sort_column.next();
        }
        KeyCode::Char('r') => {
            app.sort_direction = app.sort_direction.toggle();
        }
        KeyCode::Char(c @ '1'..='9') => {
            let idx = (c as usize) - ('1' as usize);
            if let Some(col) = SortColumn::from_index(idx) {
                if app.sort_column == col {
                    app.sort_direction = app.sort_direction.toggle();
                } else {
                    app.sort_column = col;
                    app.sort_direction = SortDirection::Asc;
                }
            }
        }
        _ => {}
    }
}

fn handle_detail_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => app.mode = AppMode::Table,
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('d') => {
            let ports = app.sorted_ports();
            if let Some(info) = ports.get(app.detail_index) {
                if info.pid == 0 {
                    app.popup = Some(Popup::Docker(DockerPopup {
                        container_name: info.process_name.clone(),
                        port: info.port,
                        selected: 0,
                    }));
                } else {
                    app.popup = Some(Popup::Kill(KillPopup {
                        pid: info.pid,
                        process_name: info.process_name.clone(),
                        port: info.port,
                        force: app.default_force,
                    }));
                }
            }
        }
        KeyCode::Char('D') => {
            let ports = app.sorted_ports();
            if let Some(info) = ports.get(app.detail_index) {
                if info.pid == 0 {
                    app.popup = Some(Popup::Docker(DockerPopup {
                        container_name: info.process_name.clone(),
                        port: info.port,
                        selected: 0,
                    }));
                } else {
                    app.popup = Some(Popup::Kill(KillPopup {
                        pid: info.pid,
                        process_name: info.process_name.clone(),
                        port: info.port,
                        force: true,
                    }));
                }
            }
        }
        _ => {}
    }
}

fn handle_filter_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Enter => {
            app.mode = AppMode::Table;
            // Clamp selection after filter applied
            let count = app.sorted_ports().len();
            if count == 0 {
                app.table_state.select(None);
            } else {
                app.table_state.select(Some(0));
            }
        }
        KeyCode::Esc => {
            app.filter_text.clear();
            app.mode = AppMode::Table;
            // Reselect after clearing filter
            let count = app.sorted_ports().len();
            if count > 0 && app.table_state.selected().is_none() {
                app.table_state.select(Some(0));
            }
        }
        KeyCode::Backspace => {
            app.filter_text.pop();
        }
        KeyCode::Char(c) => {
            app.filter_text.push(c);
        }
        _ => {}
    }
}

fn handle_kill_popup_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('y') | KeyCode::Enter => {
            if let Some(Popup::Kill(popup)) = app.popup.take() {
                app.status_message = Some((
                    match kill_process(popup.pid, popup.force) {
                        Ok("TerminateProcess") => {
                            format!("Terminated PID {}", popup.pid)
                        }
                        Ok(action) => format!("Sent {} to PID {}", action, popup.pid),
                        Err(err) => format!("Failed to kill PID {}: {}", popup.pid, err),
                    },
                    Instant::now(),
                ));
                // Refresh immediately to reflect killed process
                app.refresh_data();
            }
        }
        KeyCode::Char('n') | KeyCode::Esc => {
            app.popup = None;
        }
        _ => {}
    }
}

fn handle_docker_popup_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('j') | KeyCode::Down => {
            if let Some(Popup::Docker(ref mut p)) = app.popup {
                p.selected = (p.selected + 1).min(2);
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if let Some(Popup::Docker(ref mut p)) = app.popup {
                p.selected = p.selected.saturating_sub(1);
            }
        }
        KeyCode::Enter => {
            if let Some(Popup::Docker(popup)) = app.popup.take() {
                let msg = match popup.selected {
                    0 => run_docker_action("stop", &popup.container_name),
                    1 => run_docker_action("restart", &popup.container_name),
                    2 => {
                        let logs = run_docker_logs(&popup.container_name);
                        format!("Logs: {}", logs.lines().last().unwrap_or("(empty)"))
                    }
                    _ => String::new(),
                };
                app.status_message = Some((msg, Instant::now()));
                app.refresh_data();
            }
        }
        KeyCode::Esc | KeyCode::Char('n') => {
            app.popup = None;
        }
        _ => {}
    }
}

// ── Main entry point ─────────────────────────────────────────────────

pub fn run_tui(
    target: Option<&str>,
    show_all: bool,
    wide: bool,
    force: bool,
    no_color: bool,
    docker: bool,
    styles: StyleConfig,
) -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = App::new(target, show_all, wide, force, no_color, docker, styles);

    let tick_rate = Duration::from_secs(1);

    loop {
        terminal.draw(|frame| render(frame, &mut app))?;

        if app.should_quit {
            break;
        }

        // Refresh data every tick
        if app.last_refresh.elapsed() >= tick_rate {
            app.refresh_data();
        }

        // Wait for events with timeout to next tick
        let remaining = tick_rate
            .checked_sub(app.last_refresh.elapsed())
            .unwrap_or(Duration::ZERO);

        if event::poll(remaining)? {
            if let Event::Key(key) = event::read()? {
                // Only handle Press events (not Release/Repeat)
                if key.kind == KeyEventKind::Press {
                    handle_key(&mut app, key.code, key.modifiers);
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    fn make_port_info(port: u16, name: &str, cmd: &str) -> PortInfo {
        PortInfo {
            port,
            protocol: "TCP".to_string(),
            pid: port as u32 * 100,
            process_name: name.to_string(),
            command: cmd.to_string(),
            user: "test".to_string(),
            state: crate::TcpState::Listen,
            memory_bytes: 1024 * 1024,
            cpu_seconds: 1.0,
            start_time: Some(SystemTime::now() - Duration::from_secs(60)),
            children: 0,
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    fn make_test_app(ports: Vec<PortInfo>) -> App {
        App {
            ports,
            docker_enabled: false,
            docker_map: DockerPortMap::default(),
            table_state: TableState::default(),
            mode: AppMode::Table,
            show_all: false,
            filter_text: String::new(),
            popup: None,
            target: None,
            styles: StyleConfig::default(),
            theme: TuiTheme::no_color(),
            wide: false,
            default_force: false,
            should_quit: false,
            last_refresh: Instant::now(),
            detail_index: 0,
            status_message: None,
            sort_column: SortColumn::Port,
            sort_direction: SortDirection::Asc,
        }
    }

    #[test]
    fn filtered_ports_no_filter() {
        let mut app = make_test_app(vec![
            make_port_info(3000, "node", "next dev"),
            make_port_info(5432, "postgres", "postgres"),
        ]);
        assert_eq!(app.filtered_ports().len(), 2);

        // Filter by text
        app.filter_text = "node".to_string();
        let filtered = app.filtered_ports();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].port, 3000);
    }

    #[test]
    fn filtered_ports_by_port_number() {
        let mut app = make_test_app(vec![
            make_port_info(3000, "node", "next dev"),
            make_port_info(5432, "postgres", "postgres"),
        ]);

        app.filter_text = "5432".to_string();
        let filtered = app.filtered_ports();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].port, 5432);
    }

    #[test]
    fn filtered_ports_with_target() {
        let mut app = make_test_app(vec![
            make_port_info(3000, "node", "next dev"),
            make_port_info(5432, "postgres", "postgres"),
            make_port_info(8080, "node", "express"),
        ]);
        app.target = Some("node".to_string());

        let filtered = app.filtered_ports();
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|p| p.process_name == "node"));
    }

    #[test]
    fn filtered_ports_target_port_number() {
        let mut app = make_test_app(vec![
            make_port_info(3000, "node", "next dev"),
            make_port_info(5432, "postgres", "postgres"),
        ]);
        app.target = Some("3000".to_string());

        let filtered = app.filtered_ports();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].port, 3000);
    }

    #[test]
    fn filtered_ports_case_insensitive() {
        let mut app = make_test_app(vec![
            make_port_info(3000, "Node", "Next dev"),
            make_port_info(5432, "postgres", "postgres"),
        ]);

        app.filter_text = "NODE".to_string();
        let filtered = app.filtered_ports();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].port, 3000);
    }

    #[test]
    fn filtered_ports_empty_result() {
        let mut app = make_test_app(vec![make_port_info(3000, "node", "next dev")]);

        app.filter_text = "nonexistent".to_string();
        assert!(app.filtered_ports().is_empty());
    }

    #[test]
    fn filtered_ports_matches_docker_container_name() {
        let mut app = make_test_app(vec![make_port_info(3000, "node", "next dev")]);
        app.docker_enabled = true;
        app.docker_map.insert(
            3000,
            vec![DockerPortOwner {
                container_id: "0123456789abcdef".to_string(),
                container_name: "web".to_string(),
                image: "nginx:latest".to_string(),
                container_port: 80,
                protocol: "TCP".to_string(),
            }],
        );

        app.filter_text = "web".to_string();
        let filtered = app.filtered_ports();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].port, 3000);
    }

    #[test]
    fn filtered_ports_target_matches_docker_image() {
        let mut app = make_test_app(vec![make_port_info(5432, "postgres", "postgres")]);
        app.docker_enabled = true;
        app.docker_map.insert(
            5432,
            vec![DockerPortOwner {
                container_id: "aaaaaaaaaaaa1111".to_string(),
                container_name: "db".to_string(),
                image: "postgres:16".to_string(),
                container_port: 5432,
                protocol: "TCP".to_string(),
            }],
        );
        app.target = Some("postgres:16".to_string());

        let filtered = app.filtered_ports();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].port, 5432);
    }

    #[test]
    fn sorted_ports_by_port_asc() {
        let app = make_test_app(vec![
            make_port_info(8080, "node", "express"),
            make_port_info(3000, "node", "next dev"),
            make_port_info(5432, "postgres", "postgres"),
        ]);
        let sorted = app.sorted_ports();
        assert_eq!(sorted[0].port, 3000);
        assert_eq!(sorted[1].port, 5432);
        assert_eq!(sorted[2].port, 8080);
    }

    #[test]
    fn sorted_ports_by_port_desc() {
        let mut app = make_test_app(vec![
            make_port_info(3000, "node", "next dev"),
            make_port_info(8080, "node", "express"),
            make_port_info(5432, "postgres", "postgres"),
        ]);
        app.sort_direction = SortDirection::Desc;
        let sorted = app.sorted_ports();
        assert_eq!(sorted[0].port, 8080);
        assert_eq!(sorted[1].port, 5432);
        assert_eq!(sorted[2].port, 3000);
    }

    #[test]
    fn sorted_ports_by_process() {
        let mut app = make_test_app(vec![
            make_port_info(3000, "node", "next dev"),
            make_port_info(5432, "postgres", "postgres"),
            make_port_info(6379, "redis", "redis-server"),
        ]);
        app.sort_column = SortColumn::Process;
        let sorted = app.sorted_ports();
        assert_eq!(sorted[0].process_name, "node");
        assert_eq!(sorted[1].process_name, "postgres");
        assert_eq!(sorted[2].process_name, "redis");
    }

    #[test]
    fn sorted_ports_by_mem() {
        let mut p1 = make_port_info(3000, "node", "next dev");
        let mut p2 = make_port_info(5432, "postgres", "postgres");
        let mut p3 = make_port_info(6379, "redis", "redis-server");
        p1.memory_bytes = 200 * 1024 * 1024;
        p2.memory_bytes = 50 * 1024 * 1024;
        p3.memory_bytes = 10 * 1024 * 1024;

        let mut app = make_test_app(vec![p1, p2, p3]);
        app.sort_column = SortColumn::Mem;
        app.sort_direction = SortDirection::Desc;
        let sorted = app.sorted_ports();
        assert_eq!(sorted[0].port, 3000); // highest mem
        assert_eq!(sorted[1].port, 5432);
        assert_eq!(sorted[2].port, 6379); // lowest mem
    }

    #[test]
    fn sorted_ports_uptime_none_sorts_last() {
        let mut p1 = make_port_info(3000, "node", "next dev");
        let mut p2 = make_port_info(5432, "postgres", "postgres");
        p1.start_time = None;
        p2.start_time = Some(SystemTime::now() - Duration::from_secs(3600));

        let mut app = make_test_app(vec![p1, p2]);
        app.sort_column = SortColumn::Uptime;
        let sorted = app.sorted_ports();
        // p2 has a start_time, p1 has None → p2 first
        assert_eq!(sorted[0].port, 5432);
        assert_eq!(sorted[1].port, 3000);
    }

    #[test]
    fn sort_column_cycle() {
        let col = SortColumn::Port;
        assert_eq!(col.next(), SortColumn::Proto);
        assert_eq!(col.prev(), SortColumn::Command);
        assert_eq!(SortColumn::Command.next(), SortColumn::Port);
    }

    #[test]
    fn sort_direction_toggle() {
        assert_eq!(SortDirection::Asc.toggle(), SortDirection::Desc);
        assert_eq!(SortDirection::Desc.toggle(), SortDirection::Asc);
    }

    #[test]
    fn sort_column_from_index() {
        assert_eq!(SortColumn::from_index(0), Some(SortColumn::Port));
        assert_eq!(SortColumn::from_index(3), Some(SortColumn::Address));
        assert_eq!(SortColumn::from_index(8), Some(SortColumn::Command));
        assert_eq!(SortColumn::from_index(9), None);
    }
}
