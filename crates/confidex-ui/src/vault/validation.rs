use super::*;
#[cfg(test)]
mod tests;

pub(super) struct Problem<'a> {
    pub target: egui::Id,
    pub name: &'a str,
    pub message: &'static str,
    order: (usize, bool),
}

impl VaultApp {
    pub(super) fn record_problems<'a>(&self, draft: &'a Draft) -> Vec<Problem<'a>> {
        let list = egui::Id::unique(("record-fields", draft.record));
        let mut problems = Vec::new();
        for (index, field) in draft.fields.iter().enumerate() {
            let id = list.with(self.field_ids.get(index).copied().unwrap_or(0));
            let message = self
                .totp_problem(id, field)
                .or_else(|| wifi::problem(field, &draft.fields, &self.field_ids))
                .or_else(|| (!dates::valid(field)).then_some("field-invalid-date"))
                .or_else(|| (!locations::valid(field)).then_some("field-invalid-coordinates"));
            if let Some(message) = message {
                problems.push(Problem {
                    target: id,
                    name: &field.name,
                    message,
                    order: (index, true),
                });
            }
        }
        if let Some(sections) = &draft.sections
            && app::sections::validate(sections, draft.fields.len()).is_err()
        {
            let mut end = 0;
            for (index, section) in sections.iter().enumerate() {
                let next = section.start.checked_add(section.count);
                if section.name.len() > 4096
                    || section.start < end
                    || next.is_none_or(|end| end > draft.fields.len())
                {
                    problems.push(Problem {
                        target: list
                            .with("sections")
                            .with(self.section_ids.get(index).copied().unwrap_or(0)),
                        name: &section.name,
                        message: "vault-error-input",
                        order: (section.start, false),
                    });
                }
                end = next.unwrap_or(usize::MAX);
            }
        }
        problems.sort_by_key(|problem| problem.order);
        problems
    }
    pub(super) fn record_valid(&self, draft: &Draft) -> bool {
        !draft.title.trim().is_empty()
            && !self.ssh.is_open()
            && self.tag_editor.problem(&draft.tags).is_none()
            && self.record_problems(draft).is_empty()
            && draft.sections.as_ref().is_none_or(|sections| {
                app::sections::validate(sections, draft.fields.len()).is_ok()
            })
    }
    pub(super) fn validation_summary(
        &mut self,
        ui: &mut egui::Ui,
        draft: &Draft,
    ) -> Option<egui::Id> {
        let problems = self.record_problems(draft);
        let first = problems.first()?;
        let mut target = None;
        layout::grid(
            ui,
            "record-validation-actions",
            1,
            160.,
            1,
            Metrics::SM,
            |ui, _| {
                if self.button(ui, "first-problem", "vault-first-problem", !self.busy) {
                    target = Some(first.target);
                }
            },
        );
        let mut args = fluent_bundle::FluentArgs::new();
        args.set("count", problems.len() as i64);
        let response = ui.colored_label(
            THEMES[self.theme].colors.error,
            self.locale.format("vault-validation", &args),
        );
        self.bounds
            .insert("record-validation".into(), response.rect);
        for problem in problems {
            let name = if problem.name.is_empty() {
                self.locale.text("gallery-wifi-unnamed")
            } else {
                let mut name: String = problem.name.chars().take(80).collect();
                if problem.name.chars().count() > 80 {
                    name.push('…');
                }
                name
            };
            ui.label(format!("{name}: {}", self.locale.text(problem.message)));
        }
        ui.add_space(Metrics::LG);
        target
    }
}
