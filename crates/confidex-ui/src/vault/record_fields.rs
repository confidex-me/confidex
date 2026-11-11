use super::*;
#[cfg(test)]
mod tests;

struct FieldView<'a> {
    record: RecordId,
    title: &'a str,
    fields: &'a [app::Field],
    ids: &'a [u64],
    list: egui::Id,
    editing: bool,
    enabled: bool,
}

#[derive(Default)]
struct Layout {
    fields: Vec<(egui::Id, egui::Rect, usize)>,
    groups: Vec<(egui::Id, egui::Rect, usize)>,
    field_action: Option<(usize, design::field::Action)>,
    group_action: Option<(usize, design::field::Action)>,
    added: Option<(String, usize, Option<usize>)>,
}

fn group_at(sections: &[app::sections::Section], field: usize) -> Option<usize> {
    sections
        .iter()
        .position(|section| section.start <= field && field < section.end())
}

impl VaultApp {
    pub(super) fn record_fields(
        &mut self,
        ui: &mut egui::Ui,
        draft: &mut Draft,
        focus: Option<egui::Id>,
    ) {
        let list = egui::Id::unique(("record-fields", draft.record));
        let groups = list.with("sections");
        let source = draft.fields.clone();
        let ids = self.field_ids.clone();
        let view = FieldView {
            record: draft.record,
            title: &draft.title,
            fields: &source,
            ids: &ids,
            list,
            editing: self.editing,
            enabled: !self.busy,
        };
        let count = draft.sections.as_ref().map_or(0, Vec::len);
        if self.section_ids.len() != count {
            self.section_ids = (self.next_field..self.next_field + count as u64).collect();
            self.next_field += count as u64;
        }
        let mut layout = Layout::default();
        let added_focus = self
            .pending_field_focus
            .take()
            .filter(|_| !self.shortcuts_blocked && view.editing && view.enabled);
        let focus = focus.or(added_focus.map(|(field, _)| field));
        let mut cursor = 0;
        if let Some(sections) = draft.sections.as_mut().filter(|sections| {
            let mut end = 0;
            sections.iter().all(|section| {
                let next = section.start.checked_add(section.count);
                let valid =
                    section.start >= end && next.is_some_and(|end| end <= draft.fields.len());
                end = next.unwrap_or(usize::MAX);
                valid
            })
        }) {
            for (index, section) in sections.iter_mut().enumerate() {
                self.field_range(
                    ui,
                    &mut draft.fields[cursor..section.start],
                    cursor,
                    &view,
                    &mut layout,
                    false,
                );
                let id = groups.with(self.section_ids[index]);
                let kind = self.locale.text("field-section");
                let move_label = self.locale.text("vault-move-field");
                let remove_label = self.locale.text("field-ungroup");
                let add_label = self.locale.text("vault-add-field");
                let start = section.start;
                let end = section.end();
                let position = layout.fields.len();
                let response = ui
                    .add_enabled_ui(view.enabled, |ui| {
                        design::section::Section {
                            header: design::field::Field {
                                id,
                                list: groups,
                                name: &mut section.name,
                                kind: &kind,
                                editing: view.editing,
                                move_label: &move_label,
                                remove_label: &remove_label,
                            },
                            add_label: &add_label,
                        }
                        .show(ui, THEMES[self.theme].colors, |ui| {
                            self.field_range(
                                ui,
                                &mut draft.fields[start..end],
                                start,
                                &view,
                                &mut layout,
                                true,
                            );
                        })
                    })
                    .inner;
                if response.name.changed() {
                    self.attachments.invalidate_size();
                }
                let prefix = format!("section-{index}");
                self.hits
                    .insert(format!("{prefix}-name"), response.name.rect);
                self.hits
                    .insert(format!("{prefix}-handle"), response.handle.rect);
                self.bounds.insert(prefix.clone(), response.rect);
                if let Some(remove) = &response.remove {
                    self.hits.insert(format!("{prefix}-remove"), remove.rect);
                }
                if let Some(action) = response.action {
                    layout.group_action = Some((index, action));
                }
                if let Some(add) = response.inner.1 {
                    self.hits.insert(format!("{prefix}-add"), add.rect);
                    design::menu(ui, &add, |ui| {
                        self.bounds.insert(
                            "field-menu".into(),
                            egui::Rect::from_x_y_ranges(
                                ui.max_rect().x_range(),
                                ui.clip_rect().y_range(),
                            ),
                        );
                        if let Some(kind) = self.field_choices(ui, &format!("{prefix}-add")) {
                            layout.added = Some((kind, end, Some(index)));
                        }
                    });
                }
                if section.name.len() > 4096 {
                    ui.colored_label(
                        THEMES[self.theme].colors.error,
                        self.locale.text("vault-error-input"),
                    );
                }
                // An empty header is also a destination for independent fields.
                let header = response.name.rect.union(response.handle.rect);
                layout.fields.insert(position, (id, header, start));
                layout.groups.push((id, response.rect, index));
                cursor = end;
            }
        }
        self.field_range(
            ui,
            &mut draft.fields[cursor..],
            cursor,
            &view,
            &mut layout,
            false,
        );
        if let Some(target) = focus
            && let Some((_, rect, _)) = layout.fields.iter().find(|(id, _, _)| *id == target)
        {
            ui.scroll_to_rect(*rect, Some(egui::Align::Min));
            let input = added_focus
                .filter(|(field, _)| *field == target)
                .map_or_else(|| target.with(("header", "name")), |(_, input)| input);
            ui.memory_mut(|memory| memory.request_focus(input));
        }
        if !view.editing || !view.enabled {
            return;
        }
        let p = THEMES[self.theme].colors;
        let targets: Vec<_> = layout
            .fields
            .iter()
            .map(|(id, rect, _)| (*id, *rect))
            .collect();
        let dropped = design::field::drop_target(ui, p, list, &targets).and_then(|(key, slot)| {
            let from = ids.iter().position(|id| list.with(*id) == key)?;
            let slot = layout
                .fields
                .get(slot)
                .map_or(draft.fields.len(), |(_, _, field)| *field);
            let target = ui.ctx().pointer_interact_pos().and_then(|pos| {
                layout
                    .groups
                    .iter()
                    .find(|(_, rect, _)| rect.contains(pos))
                    .map(|(_, _, index)| *index)
            });
            Some((from, slot, target))
        });
        let group_targets: Vec<_> = layout
            .groups
            .iter()
            .map(|(id, rect, _)| (*id, *rect))
            .collect();
        if let Some((key, slot)) = design::field::drop_target(ui, p, groups, &group_targets)
            && let Some(from) = self
                .section_ids
                .iter()
                .position(|id| groups.with(*id) == key)
        {
            let to = slot.saturating_sub(usize::from(from < slot));
            self.move_group(draft, from, to);
        } else if let Some((from, action)) = layout.group_action {
            match action {
                design::field::Action::Remove => {
                    draft.sections.as_mut().unwrap().remove(from);
                    self.section_ids.remove(from);
                }
                design::field::Action::Up if from > 0 => self.move_group(draft, from, from - 1),
                design::field::Action::Down if from + 1 < count => {
                    self.move_group(draft, from, from + 1)
                }
                _ => {}
            }
            self.attachments.invalidate_size();
        } else if let Some((index, action)) = layout.field_action {
            match action {
                design::field::Action::Remove => {
                    let key = self.field_ids.remove(index);
                    self.ssh.removed(key);
                    let id = list.with(key).value();
                    self.totp_fields.remove(&id);
                    self.totp_times.remove(&id);
                    self.card_fields.remove(&id);
                    self.date_fields.remove(&id);
                    self.wifi_fields.remove(&id);
                    draft.fields.remove(index);
                    if let Some(sections) = &mut draft.sections {
                        app::sections::remove_field(sections, index);
                    }
                    self.revealed.retain(|(field, _)| *field != key);
                    self.clipboard.clear();
                }
                design::field::Action::Up | design::field::Action::Down => {
                    let neighbor = if action == design::field::Action::Up {
                        index.saturating_sub(1)
                    } else {
                        (index + 1).min(draft.fields.len() - 1)
                    };
                    let target = draft
                        .sections
                        .as_deref()
                        .and_then(|sections| group_at(sections, neighbor));
                    let slot = neighbor + usize::from(neighbor > index);
                    self.move_record_field(draft, index, slot, target);
                }
            }
            self.attachments.invalidate_size();
        } else if let Some((from, slot, target)) = dropped {
            self.move_record_field(draft, from, slot, target);
            self.attachments.invalidate_size();
        } else if let Some((kind, at, target)) = layout.added {
            self.insert_record_field(draft, &kind, at, target);
        }
    }

    fn field_range(
        &mut self,
        ui: &mut egui::Ui,
        fields: &mut [app::Field],
        start: usize,
        view: &FieldView<'_>,
        layout: &mut Layout,
        grouped: bool,
    ) {
        let mut shown = false;
        for (offset, field) in fields.iter_mut().enumerate() {
            if !view.editing && !field_visible(field) {
                continue;
            }
            if grouped && shown {
                ui.separator();
            }
            shown = true;
            let index = start + offset;
            let response = self.record_field(ui, field, index, view, grouped);
            if let Some(action) = response.action {
                layout.field_action = Some((index, action));
            }
            layout
                .fields
                .push((view.list.with(view.ids[index]), response.rect, index));
        }
    }

    pub(super) fn field_choices(&mut self, ui: &mut egui::Ui, prefix: &str) -> Option<String> {
        let mut chosen = None;
        for kind in app::FIELD_KINDS {
            let response = ui.button(field_label(&self.locale, kind));
            self.hits.insert(format!("{prefix}-{kind}"), response.rect);
            if response.clicked() {
                chosen = Some((*kind).into());
                ui.close();
            }
        }
        chosen
    }

    fn move_record_field(
        &mut self,
        draft: &mut Draft,
        from: usize,
        slot: usize,
        target: Option<usize>,
    ) {
        if let Some(sections) = &mut draft.sections {
            app::sections::move_field(sections, from, slot, target);
        }
        design::field::move_to_slot(&mut draft.fields, from, slot);
        design::field::move_to_slot(&mut self.field_ids, from, slot);
    }

    pub(super) fn insert_record_field(
        &mut self,
        draft: &mut Draft,
        kind: &str,
        at: usize,
        target: Option<usize>,
    ) {
        match app::field(kind) {
            Ok(mut field) => {
                field.name = field_label(&self.locale, &field.type_name);
                if let Some(sections) = &mut draft.sections
                    && (target.is_some() || at < draft.fields.len())
                {
                    app::sections::insert_field(sections, at, target);
                }
                draft.fields.insert(at, field);
                self.field_ids.insert(at, self.next_field);
                let id = egui::Id::unique(("record-fields", draft.record)).with(self.next_field);
                let input = match kind {
                    "url/v1" => id.with("url").with("input"),
                    "location/v1" => id.with("name").with("input"),
                    _ => id.with(("header", "name")),
                };
                self.pending_field_focus = Some((id, input));
                self.next_field += 1;
                self.attachments.invalidate_size();
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn move_group(&mut self, draft: &mut Draft, from: usize, to: usize) {
        let Some(sections) = &mut draft.sections else {
            return;
        };
        match app::sections::move_section(sections, draft.fields.len(), from, to) {
            Ok(order) => {
                let mut fields: Vec<_> = std::mem::take(&mut draft.fields)
                    .into_iter()
                    .map(Some)
                    .collect();
                draft.fields = order
                    .iter()
                    .map(|index| fields[*index].take().unwrap())
                    .collect();
                let ids = self.field_ids.clone();
                self.field_ids = order.iter().map(|index| ids[*index]).collect();
                design::field::move_to_slot(
                    &mut self.section_ids,
                    from,
                    to + usize::from(from < to),
                );
                self.attachments.invalidate_size();
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn record_field(
        &mut self,
        ui: &mut egui::Ui,
        field: &mut app::Field,
        index: usize,
        view: &FieldView<'_>,
        grouped: bool,
    ) -> design::field::Response<()> {
        let source_name = field.name.clone();
        let key = view.ids[index];
        let id = view.list.with(key);
        let list = view.list;
        let editing = view.editing;
        let enabled = view.enabled;
        let record_id = view.record;
        let p = THEMES[self.theme].colors;
        let kind = field_label(&self.locale, &field.type_name);
        let move_label = self.locale.text("vault-move-field");
        let remove_label = self.locale.text("vault-remove-field");
        let response = ui
            .add_enabled_ui(enabled, |ui| {
                let card = design::field::Field {
                    id,
                    list,
                    name: &mut field.name,
                    kind: &kind,
                    editing,
                    move_label: &move_label,
                    remove_label: &remove_label,
                };
                let body = |ui: &mut egui::Ui| {
                    let ssh = field.type_name == "ssh/v1";
                    if ssh && editing && self.ssh_editor(ui, record_id, key) {
                        return;
                    }
                    if editing && field.type_name == "location/v1" && !field.protected {
                        self.location_field(ui, id, &view.fields[index], &mut field.values);
                        return;
                    }
                    if editing
                        && design::date::Precision::from_type(&field.type_name).is_some()
                        && (!field.protected || self.revealed.contains(&(key, "date".into())))
                    {
                        self.date_field(ui, id, key, &view.fields[index], &mut field.values);
                        return;
                    }
                    if field.type_name == "photo/v1" {
                        self.photo_field(
                            ui,
                            record_id,
                            key,
                            field.data.as_ref(),
                            &field.values,
                            editing,
                        );
                        if editing {
                            self.file_drop_hint(ui, key);
                        }
                        return;
                    }
                    if field.type_name == "file/v1" {
                        self.file_field(
                            ui,
                            record_id,
                            key,
                            field.data.as_ref(),
                            &field.values,
                            editing,
                        );
                        if editing {
                            self.file_drop_hint(ui, key);
                        }
                        return;
                    }
                    if field.type_name == "wifi-qr/v1" {
                        self.wifi_field(ui, id, &mut field.values, view.fields, view.ids, editing);
                        return;
                    }
                    if field.type_name == "card/v1" {
                        self.card_field(ui, id, &view.fields[index], &mut field.values, editing);
                        return;
                    }
                    if field.type_name == "totp/v1" {
                        self.totp_field(
                            ui,
                            id,
                            &view.fields[index],
                            editing.then_some((&mut field.values, &mut field.data)),
                        );
                        return;
                    }
                    if field.type_name == "secure-note/v1"
                        || field.type_name == "note/v1" && field.protected
                    {
                        let response = ui
                            .add_enabled_ui(editing, |ui| {
                                design::checkbox(
                                    ui,
                                    &mut field.protected,
                                    self.locale.text("vault-protect-note"),
                                )
                            })
                            .inner;
                        self.hits
                            .insert(format!("protected-{index}"), response.rect);
                        if response.changed() {
                            field.type_name = if field.protected {
                                "secure-note/v1"
                            } else {
                                "note/v1"
                            }
                            .into();
                            self.revealed.retain(|(field, _)| *field != key);
                        }
                    }
                    let mut keys: Vec<_> = field.values.keys().cloned().collect();
                    keys.sort_by_key(|key| {
                        if ssh {
                            app::ssh::ROWS
                                .iter()
                                .position(|row| *row == key)
                                .unwrap_or(4)
                        } else if field.type_name == "location/v1" {
                            confidex_vault::location::FIELDS
                                .iter()
                                .position(|item| *item == key)
                                .unwrap_or(3)
                        } else {
                            match key.as_str() {
                                "username" => 0,
                                "password" | "secret" => 1,
                                "url" => 2,
                                _ => 3,
                            }
                        }
                    });
                    for value_key in keys {
                        let multiple = field.values.len() > 1;
                        let text = field.values.get_mut(&value_key).unwrap();
                        if !editing && text.is_empty() {
                            continue;
                        }
                        let label = if ssh {
                            self.locale.text(match value_key.as_str() {
                                "public_key" => "ssh-public",
                                "fingerprint" => "ssh-fingerprint",
                                "private_key" => "ssh-private",
                                _ => "ssh-type",
                            })
                        } else if design::date::Precision::from_type(&field.type_name).is_some() {
                            kind.clone()
                        } else {
                            value_label(&self.locale, &value_key)
                        };
                        if multiple {
                            design::muted(ui, p, label.clone());
                        }
                        let kind = field_kind(&field.type_name, &value_key);
                        let password = field.type_name == "password/v1";
                        let mut revealed = self.revealed.contains(&(key, value_key.clone()));
                        let value_id = id.with(&value_key);
                        let labels = [
                            "vault-copy-value",
                            "vault-copy-pending",
                            "vault-copied",
                            "vault-copy-failed",
                            "vault-reveal",
                            "vault-hide",
                            "vault-large-type",
                            "vault-empty-value",
                        ]
                        .map(|id| self.locale.text(id));
                        let field = value::ValueField {
                            id: value_id,
                            value: text,
                            kind,
                            protected: value_protected(
                                &field.type_name,
                                field.protected,
                                &value_key,
                            ),
                            editing: editing && !ssh,
                            enabled,
                            revealed: &mut revealed,
                            feedback: self.clipboard.state(value_id),
                            labels: value::Labels {
                                copy: &labels[0],
                                pending: &labels[1],
                                copied: &labels[2],
                                failed: &labels[3],
                                show: &labels[4],
                                hide: &labels[5],
                                large: &labels[6],
                                empty: &labels[7],
                            },
                        };
                        let output = if password {
                            let output =
                                self.password_field(ui, &format!("password-{index}"), field);
                            if let Some(rect) = output.strength {
                                self.bounds
                                    .insert(format!("strength-{index}-{value_key}"), rect);
                            }
                            output.value
                        } else {
                            field.show(ui, p)
                        };
                        if output.input.changed() {
                            self.attachments.invalidate_size();
                        }
                        let field_name = if source_name.is_empty() {
                            label.clone()
                        } else if multiple {
                            format!("{source_name} · {label}")
                        } else {
                            source_name.clone()
                        };
                        self.large_value(
                            ui,
                            large_type::Value {
                                id: value_id,
                                title: view.title,
                                field: &field_name,
                                text,
                            },
                            &output,
                        );
                        if let Some(large) = &output.large {
                            self.hits
                                .insert(format!("large-{index}-{value_key}"), large.rect);
                        }
                        if revealed {
                            self.revealed.insert((key, value_key.clone()));
                        } else {
                            self.revealed.remove(&(key, value_key.clone()));
                        }
                        if output.input.changed() {
                            self.clipboard.invalidate(value_id);
                        }
                        if output.copy.clicked() {
                            self.clipboard.request(ui.ctx(), value_id, text.clone());
                        }
                        self.hits
                            .insert(format!("value-{index}-{value_key}"), output.input.rect);
                        self.hits
                            .insert(format!("copy-{index}-{value_key}"), output.copy.rect);
                        if let Some(reveal) = output.reveal {
                            self.hits
                                .insert(format!("reveal-{index}-{value_key}"), reveal.rect);
                        }
                        self.bounds
                            .insert(format!("value-{index}-{value_key}"), output.viewport);
                    }
                    if field.type_name == "location/v1"
                        && !field.values.is_empty()
                        && !locations::valid_values(&field.values)
                    {
                        ui.colored_label(p.error, self.locale.text("field-invalid-coordinates"));
                    }
                    if ssh {
                        self.ssh_actions(
                            ui,
                            record_id,
                            key,
                            &mut field.values,
                            &mut field.data,
                            editing,
                        );
                        if editing {
                            self.file_drop_hint(ui, key);
                        }
                    }
                    if field.opaque > 0
                        || field.values.is_empty()
                            && field.data.as_ref().is_some_and(|data| !data.is_empty())
                    {
                        design::muted(ui, p, self.locale.text("vault-opaque-fields"));
                    }
                };
                if grouped {
                    card.show_row(ui, p, body)
                } else {
                    card.show(ui, p, body)
                }
            })
            .inner;
        self.record_file_drop(ui, record_id, key, &field.type_name, index, &response);
        self.hits
            .insert(format!("field-name-{index}"), response.name.rect);
        if response.name.changed() {
            self.attachments.invalidate_size();
        }
        self.hits
            .insert(format!("field-handle-{index}"), response.handle.rect);
        self.bounds.insert(format!("field-{index}"), response.rect);
        self.bounds
            .insert(format!("field-type-{index}"), response.kind.rect);
        if let Some(remove) = &response.remove {
            self.hits.insert(format!("remove-{index}"), remove.rect);
        }
        response
    }
}
