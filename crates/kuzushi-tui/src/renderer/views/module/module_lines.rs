use super::*;

pub(crate) fn module_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let Some(module_id) = &app.focused_module else {
        return catalog_lines(app, area);
    };
    let Some(module) = app
        .registry
        .modules()
        .find(|module| module.metadata().id == *module_id)
    else {
        return catalog_lines(app, area);
    };

    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(transcript_line(
        ">",
        &format!("/use {}", module.metadata().id),
        false,
    ));
    let primary_tool = module
        .tools()
        .first()
        .map(|tool| tool.name.as_str())
        .unwrap_or("no-tool");
    lines.push(transcript_line(
        "use",
        &format!(
            "focused module {} · primary tool {}",
            module.metadata().id,
            primary_tool
        ),
        false,
    ));
    lines.push(Line::from(vec![
        Span::styled(module.metadata().id.clone(), theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(module.metadata().name.clone(), theme::muted()),
    ]));
    lines.push(indent(
        muted(&short_sentence(
            &module.metadata().description,
            area.width.saturating_sub(2) as usize,
        )),
        2,
    ));
    lines.push(blank());

    if module.tools().is_empty() {
        lines.push(muted("No shell tools are exposed by this module."));
    } else {
        lines.push(divider("TOOLS", area.width));
        for tool in module.tools() {
            lines.push(tool_console_row(
                &tool.name,
                &tool.description,
                tool.headless,
                area.width,
            ));
        }
    }
    lines.push(blank());

    // OPTIONS — set values from the option store, per
    // `design/mockups/modules-detail.jsx::s2`.  Only show options that
    // actually have stored values; keep the panel terse for modules
    // that haven't been tuned.
    let stored_options = module_stored_options(app, module);
    if !stored_options.is_empty() {
        lines.push(divider(
            &format!("OPTIONS · {}", stored_options.len()),
            area.width,
        ));
        for (name, value) in &stored_options {
            lines.push(detail(name, value));
        }
        lines.push(blank());
    }

    // PROMPTS — `.kuzushi/prompts/<module>/<verb>.md` files on disk.
    // Lists prompt verbs the operator has overridden so they can jump
    // to the editor with `prompt edit <verb>`.
    let prompts = module_prompts_on_disk(app, &module.metadata().id);
    if !prompts.is_empty() {
        lines.push(divider(&format!("PROMPTS · {}", prompts.len()), area.width));
        for prompt in &prompts {
            lines.push(detail(&prompt.verb, &prompt.path));
        }
        lines.push(blank());
    }

    // STATS — quick session-level counts the operator can verify
    // without scrubbing the transcript.  Pulls live data only.
    let module_log_count = app
        .log
        .iter()
        .filter(|line| {
            line.prefix == module.metadata().id
                || line
                    .prefix
                    .starts_with(&format!("{}:", module.metadata().id))
        })
        .count();
    if module_log_count > 0 {
        lines.push(divider("STATS · this session", area.width));
        lines.push(detail(
            "log entries",
            &format!("{module_log_count} from `{}`", module.metadata().id),
        ));
        lines.push(detail("tools bound", &module.tools().len().to_string()));
        lines.push(blank());
    }
    let activity_label = match module.metadata().id.as_str() {
        "recon" => Some("RECENT RECON ACTIVITY"),
        "carlini-threat-hunt" => Some("RECENT THREAT-HUNT ACTIVITY"),
        "agentic-sast" => Some("RECENT AGENTIC-SAST ACTIVITY"),
        _ => None,
    };
    if let Some(label) = activity_label {
        let activity = recent_module_activity_lines(app, module.metadata().id.as_str(), 8);
        if !activity.is_empty() {
            lines.push(section_header_line(label, area.width));
            lines.extend(activity);
            lines.push(blank());
        }
    }
    lines.extend(module_playbook_lines(
        module.metadata().id.as_str(),
        primary_tool,
        area.width,
    ));

    lines
}
