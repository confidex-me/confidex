use super::*;
use confidex_storage::Head;

#[derive(Default)]
pub(super) struct View {
    pub rows: Vec<app::DeletedVersion>,
    pub next: Option<Head>,
}

impl VaultApp {
    pub(super) fn show_trash(&mut self) {
        self.draft = None;
        self.history = Default::default();
        self.revealed.clear();
        self.clipboard.clear();
        self.attachments.clear();
        self.large_type.clear();
        self.mobile_detail = false;
        self.request_trash(None);
    }

    pub(super) fn show_records(&mut self) {
        self.mobile_detail = false;
        if self.trash.take().is_some() {
            self.history = Default::default();
            self.loading_more = false;
            self.request_list(None);
        }
    }

    pub(super) fn request_trash(&mut self, after: Option<Head>) {
        if after.is_none() {
            self.trash = Some(View::default());
        }
        self.request(Command::Trash { after }, false);
    }

    pub(super) fn trash_list(&mut self, ui: &mut egui::Ui) {
        let p = THEMES[self.theme].colors;
        ui.horizontal(|ui| {
            if self.icon_button(ui, "trash-back", "vault-all-items", Icon::Back, !self.busy) {
                self.show_records();
            }
            ui.label(
                RichText::new(self.locale.text("vault-trash"))
                    .semibold()
                    .color(p.text_muted),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.icon_button(
                    ui,
                    "trash-refresh",
                    "vault-refresh",
                    Icon::Refresh,
                    !self.busy,
                ) {
                    self.request_trash(None);
                }
            });
        });
        ui.add_space(Metrics::SM);
        let mut selected = None;
        let area = layout::scroll(ui, "trash", false, |ui| {
            let Some(view) = &self.trash else { return };
            if view.rows.is_empty() {
                if self.busy {
                    design::spinner(ui, p, 24., &self.locale.text("vault-working"));
                } else if self.error.is_none() {
                    ui.add_space(Metrics::XXL);
                    ui.vertical_centered(|ui| {
                        design::badge(ui, Icon::Trash, p, 44., false);
                        ui.add_space(Metrics::MD);
                        design::muted(ui, p, self.locale.text("vault-trash-empty"));
                    });
                }
            }
            for (index, version) in view.rows.iter().enumerate() {
                let title = if version.title.is_empty() {
                    self.locale.text("vault-untitled")
                } else {
                    version.title.clone()
                };
                let response = ui
                    .push_id((version.head.revision, version.source), |ui| {
                        design::record_row(
                            ui,
                            p,
                            &title,
                            &history::date(version.epoch),
                            false,
                            !self.busy,
                        )
                    })
                    .inner;
                self.hits
                    .insert(format!("trash-record-{index}"), response.rect);
                if response.clicked() {
                    selected = Some((
                        version.head.clone(),
                        version.source,
                        version.epoch,
                        response,
                    ));
                }
            }
            if let Some(next) = view.next.clone()
                && self.button(ui, "trash-more", "vault-more", !self.busy)
            {
                self.request_trash(Some(next));
            }
        });
        self.bounds.insert("list-viewport".into(), area.inner_rect);
        if let Some((head, source, epoch, response)) = selected {
            self.history
                .preview_deleted(head.clone(), source, epoch, &response);
            self.request(Command::PreviewDeleted { head, source }, false);
        }
    }
}
