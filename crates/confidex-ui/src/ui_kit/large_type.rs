//! Large type borrows the source value. State contains no secret text.
use super::{Icon, Metrics as M, fonts, value::CopyState, window};
use crate::{i18n::Localizer, theme::Palette};
use eframe::egui::{self, Align2, FontId, Id, Rect, RichText, Stroke, Vec2};

#[derive(Default)]
pub struct State {
    source: Option<Id>,
    window: window::State,
    drawn: bool,
}
pub struct Value<'a> {
    pub id: Id,
    pub title: &'a str,
    pub field: &'a str,
    pub text: &'a str,
}
pub struct Output {
    pub rect: Rect,
    pub viewport: Rect,
    pub copy: egui::Response,
    pub close: Option<egui::Response>,
}
impl State {
    pub fn is_open(&self) -> bool {
        self.window.open && self.source.is_some()
    }
    pub fn begin_frame(&mut self) {
        self.drawn = false;
    }
    pub fn end_frame(&mut self) {
        if self.is_open() && !self.drawn {
            self.clear();
        }
    }
    pub fn clear(&mut self) {
        *self = Self::default();
    }
    pub fn show(
        &mut self,
        ui: &egui::Ui,
        p: Palette,
        value: Value<'_>,
        opener: Option<&egui::Response>,
        locale: &Localizer,
        feedback: CopyState,
    ) -> Option<Output> {
        if let Some(opener) = opener
            && opener.clicked()
        {
            self.source = Some(value.id);
            self.window.open(opener);
        }
        if self.source != Some(value.id) || !self.window.open {
            return None;
        }
        self.drawn = true;
        let ctx = ui.ctx();
        let viewport = ctx.content_rect();
        let title = if value.title.trim().is_empty() {
            locale.text("vault-untitled")
        } else {
            value.title.to_owned()
        };
        let count = value.text.chars().count();
        let preferred_columns = if count > 32 {
            16
        } else if count > 4 {
            8
        } else {
            count.max(1)
        };
        let preferred_groups = preferred_columns.div_ceil(4);
        let preferred_width = (preferred_columns as f32 * 60.
            + (preferred_columns - preferred_groups) as f32 * 6.
            + (preferred_groups - 1) as f32 * M::XL
            + 2. * M::LG)
            .clamp(384., 912.);
        let preferred_cell = ((preferred_width
            - 2. * M::LG
            - 16.
            - (preferred_columns - preferred_groups) as f32 * 6.
            - (preferred_groups - 1) as f32 * M::XL)
            / preferred_columns as f32)
            .min(76.);
        let preferred_height = (count.div_ceil(preferred_columns).clamp(1, 6) as f32
            * ((preferred_cell * 1.25).min(94.) + 50.)
            + 190.)
            .min(800.);
        let mut args = fluent_bundle::FluentArgs::new();
        args.set("field", value.field);
        args.set("count", count as i64);
        let description = locale.format("large-description", &args);
        let close_label = locale.text("window-close");
        let copy_labels = [
            "vault-copy-value",
            "vault-copy-pending",
            "vault-copied",
            "vault-copy-failed",
        ]
        .map(|key| locale.text(key));
        let copy_label = &copy_labels[match feedback {
            CopyState::Idle => 0,
            CopyState::Pending => 1,
            CopyState::Copied => 2,
            CopyState::Failed => 3,
        }];
        let legend_labels =
            ["large-letter", "large-digit", "large-symbol"].map(|key| locale.text(key));
        let id = Id::unique("large-type").with(value.id);
        let output = self.window.show(
            ctx,
            p,
            window::Window {
                id,
                title: &title,
                close_label: &close_label,
                size: Vec2::new(preferred_width, preferred_height),
            },
            |ui| {
                let area = ui.available_rect_before_wrap();
                let width = area.width();
                let compact = area.height() < 200.;
                let action_size = if viewport.width() < 600. { 44. } else { 36. };
                let caption_width = (width - action_size - M::LG).max(1.);
                let show_legend = !compact;
                let label_widths = ui.fonts_mut(|fonts| {
                    legend_labels.each_ref().map(|label| {
                        fonts
                            .layout_no_wrap(
                                label.clone(),
                                super::fonts::regular(M::CAPTION),
                                p.text,
                            )
                            .size()
                            .x
                    })
                });
                let mut legend_positions = [Vec2::ZERO; 3];
                let mut cursor = Vec2::ZERO;
                let mut legend_width = 0_f32;
                for (index, label_width) in label_widths.iter().enumerate() {
                    let item_width = (18. + M::SM + label_width).min(caption_width);
                    if cursor.x > 0. && cursor.x + item_width > caption_width {
                        cursor.x = 0.;
                        cursor.y += 22. + M::XS;
                    }
                    legend_positions[index] = cursor;
                    legend_width = legend_width.max(cursor.x + item_width);
                    cursor.x += item_width + M::LG;
                }
                let legend_height = cursor.y + 22.;
                let error_height = ui.fonts_mut(|fonts| {
                    fonts
                        .layout(
                            copy_labels[3].clone(),
                            super::fonts::regular(M::CAPTION),
                            p.error,
                            caption_width,
                        )
                        .size()
                        .y
                });
                let footer_content_height = if show_legend {
                    action_size.max(legend_height).max(error_height)
                } else {
                    action_size
                };
                let footer_padding = if compact { M::SM } else { M::LG };
                let footer_height = footer_content_height + footer_padding;
                let footer_top = area.bottom() - footer_height;
                let context = ui.add(
                    egui::Label::new(
                        RichText::new(&description)
                            .font(fonts::regular(M::LABEL))
                            .color(p.text_muted),
                    )
                    .truncate(),
                );
                let grid_top = context.rect.bottom() + if compact { M::XS } else { M::LG };
                let mut grid_rect = Rect::from_min_max(
                    egui::pos2(area.left(), grid_top),
                    egui::pos2(
                        area.right(),
                        (footer_top - if compact { M::XS } else { M::LG }).max(grid_top + 1.),
                    ),
                );
                let grid_width = (width - 16.).max(1.);
                let Grid {
                    columns,
                    cell_width,
                    cell_height,
                    names,
                    row_height,
                    visual_width,
                } = grid_layout(
                    grid_width,
                    grid_rect.height(),
                    count,
                    viewport.width() < 600.,
                    compact,
                );
                let rows = count.div_ceil(columns);
                grid_rect.min.y +=
                    ((grid_rect.height() - rows as f32 * row_height) / 2.).clamp(0., M::XL);
                let mut grid = ui.new_child(
                    egui::UiBuilder::new()
                        .id_salt("large-grid")
                        .max_rect(grid_rect)
                        .layout(egui::Layout::top_down(egui::Align::Min)),
                );
                grid.set_clip_rect(grid_rect.intersect(ui.clip_rect()));
                grid.spacing_mut().item_spacing.y = 0.;
                let scroll = super::layout::scroll_rows(
                    &mut grid,
                    "large-grid",
                    grid_rect.height(),
                    row_height,
                    rows,
                    |ui, range| {
                        let mut chars = value.text.chars().skip(range.start * columns);
                        for row in range {
                            let (rect, _) = ui.allocate_exact_size(
                                Vec2::new(ui.available_width(), row_height),
                                egui::Sense::hover(),
                            );
                            let left = rect.center().x - visual_width / 2.;
                            for col in 0..columns {
                                let Some(ch) = chars.next() else {
                                    break;
                                };
                                let position = row * columns + col + 1;
                                let x = left
                                    + (col / 4) as f32 * (4. * cell_width + 18. + M::XL)
                                    + (col % 4) as f32 * (cell_width + 6.);
                                if col % 4 == 0 {
                                    let last = (position + 3).min(count);
                                    let range = if last == position {
                                        position.to_string()
                                    } else {
                                        format!("{position}–{last}")
                                    };
                                    ui.painter().text(
                                        egui::pos2(x, rect.top()),
                                        Align2::LEFT_TOP,
                                        range,
                                        FontId::monospace(11.),
                                        p.text_muted,
                                    );
                                }
                                let cell = Rect::from_min_size(
                                    egui::pos2(x, rect.top() + 18.),
                                    Vec2::new(cell_width, cell_height),
                                );
                                paint_cell(ui, p, cell, ch, position, names, locale);
                            }
                        }
                    },
                );
                ui.painter()
                    .hline(area.x_range(), footer_top, Stroke::new(1., p.border));
                let button_rect = Rect::from_min_size(
                    egui::pos2(
                        area.right() - action_size,
                        footer_top + footer_padding + (footer_content_height - action_size) / 2.,
                    ),
                    Vec2::splat(action_size),
                );
                if show_legend {
                    let caption_height = if feedback == CopyState::Failed {
                        error_height
                    } else {
                        legend_height
                    };
                    let caption_top =
                        footer_top + footer_padding + (footer_content_height - caption_height) / 2.;
                    let caption_rect = Rect::from_min_size(
                        egui::pos2(
                            area.left()
                                + if feedback == CopyState::Failed {
                                    0.
                                } else {
                                    caption_width - legend_width
                                },
                            caption_top,
                        ),
                        Vec2::new(
                            if feedback == CopyState::Failed {
                                caption_width
                            } else {
                                legend_width
                            },
                            caption_height,
                        ),
                    );
                    if feedback == CopyState::Failed {
                        let mut caption = ui.new_child(
                            egui::UiBuilder::new()
                                .id_salt("large-copy-error")
                                .max_rect(caption_rect),
                        );
                        caption.add(
                            egui::Label::new(
                                RichText::new(&copy_labels[3])
                                    .font(fonts::regular(M::CAPTION))
                                    .color(p.error),
                            )
                            .wrap(),
                        );
                    } else {
                        for (index, (sample, label)) in
                            ['a', '7', '#'].into_iter().zip(&legend_labels).enumerate()
                        {
                            let point = caption_rect.min + legend_positions[index];
                            let sample_rect = Rect::from_min_size(point, Vec2::new(18., 22.));
                            paint_cell(ui, p, sample_rect, sample, 0, false, locale);
                            let label_width =
                                (caption_rect.right() - sample_rect.right() - M::SM).max(1.);
                            let galley = ui.fonts_mut(|fonts| {
                                let mut job = egui::text::LayoutJob::simple(
                                    label.clone(),
                                    super::fonts::regular(M::CAPTION),
                                    p.text_muted,
                                    label_width,
                                );
                                job.wrap.max_rows = 1;
                                fonts.layout_job(job)
                            });
                            ui.painter().galley(
                                egui::pos2(
                                    sample_rect.right() + M::SM,
                                    sample_rect.center().y - galley.size().y / 2.,
                                ),
                                galley,
                                p.text_muted,
                            );
                            ui.interact(
                                Rect::from_min_size(
                                    egui::pos2(sample_rect.right() + M::SM, sample_rect.top()),
                                    Vec2::new(label_widths[index].min(label_width), 22.),
                                ),
                                ui.scope_id().with(("legend", index)),
                                egui::Sense::hover(),
                            )
                            .widget_info(|| {
                                egui::WidgetInfo::labeled(egui::Role::Label, true, label)
                            });
                        }
                    }
                }
                let mut actions = ui.new_child(
                    egui::UiBuilder::new()
                        .id_salt("large-copy")
                        .max_rect(button_rect)
                        .layout(egui::Layout::top_down(egui::Align::Min)),
                );
                let mut copy_palette = p;
                copy_palette.text_muted = match feedback {
                    CopyState::Copied => p.success,
                    CopyState::Failed => p.error,
                    _ => p.text,
                };
                let icon = if feedback == CopyState::Copied {
                    Icon::Check
                } else {
                    Icon::Copy
                };
                let copy = super::icon_button_sized(
                    &mut actions,
                    copy_palette,
                    copy_label,
                    icon,
                    feedback != CopyState::Pending && count != 0,
                    action_size,
                );
                (scroll.inner_rect, copy)
            },
        )?;
        if !self.window.open {
            self.source = None;
        }
        Some(Output {
            rect: output.rect,
            viewport: output.inner.0,
            copy: output.inner.1,
            close: output.close,
        })
    }
}
struct Grid {
    columns: usize,
    cell_width: f32,
    cell_height: f32,
    names: bool,
    row_height: f32,
    visual_width: f32,
}
fn grid_layout(width: f32, height: f32, count: usize, mobile: bool, compact: bool) -> Grid {
    let max_groups = count.div_ceil(4).clamp(1, 4);
    let groups = if mobile {
        1
    } else {
        ((width + M::XL) / (4. * 44. + 18. + M::XL))
            .floor()
            .clamp(1., max_groups as f32) as usize
    };
    let layout = |groups: usize| {
        let columns = (groups * 4).min(count.max(1));
        let cell_width = ((width - (columns - groups) as f32 * 6. - (groups - 1) as f32 * M::XL)
            / columns as f32)
            .min(76.);
        let mut cell_height = (cell_width * 1.25).clamp(
            if compact { 36. } else { 52. },
            if compact { 68. } else { 94. },
        );
        if compact {
            cell_height = cell_height.min((height - 18.).max(24.));
        }
        let names = !mobile && !compact && cell_width >= 36.;
        Grid {
            columns,
            cell_width,
            cell_height,
            names,
            row_height: 18. + cell_height + if names { 32. } else { M::LG },
            visual_width: columns as f32 * cell_width
                + (columns - groups) as f32 * 6.
                + (groups - 1) as f32 * M::XL,
        }
    };
    let preferred = layout(groups);
    if !mobile && count.div_ceil(preferred.columns) as f32 * preferred.row_height > height {
        for groups in groups + 1..=max_groups {
            let candidate = layout(groups);
            if candidate.cell_width < 40. {
                break;
            }
            if count.div_ceil(candidate.columns) as f32 * candidate.row_height <= height {
                return candidate;
            }
        }
    }
    preferred
}
fn paint_cell(
    ui: &egui::Ui,
    p: Palette,
    rect: Rect,
    ch: char,
    position: usize,
    names: bool,
    locale: &Localizer,
) {
    if !ui.is_rect_visible(rect.expand(24.)) {
        return;
    }
    let digit = ch.is_numeric();
    let symbol = !ch.is_alphanumeric();
    let color = if digit || symbol { p.accent } else { p.text };
    let sample = position == 0;
    let radius = if sample { 3. } else { 8. };
    ui.painter().rect_filled(
        rect,
        radius,
        if symbol {
            p.accent.gamma_multiply(0.08)
        } else {
            p.control
        },
    );
    if symbol {
        let r = rect.shrink(0.5);
        let points = [
            r.left_top() + egui::vec2(radius, 0.),
            r.right_top() - egui::vec2(radius, 0.),
            r.right_top() + egui::vec2(0., radius),
            r.right_bottom() - egui::vec2(0., radius),
            r.right_bottom() - egui::vec2(radius, 0.),
            r.left_bottom() + egui::vec2(radius, 0.),
            r.left_bottom() - egui::vec2(0., radius),
            r.left_top() + egui::vec2(0., radius),
            r.left_top() + egui::vec2(radius, 0.),
        ];
        ui.painter().extend(egui::Shape::dashed_line(
            &points,
            Stroke::new(1., p.accent.gamma_multiply(0.6)),
            4.,
            4.,
        ));
    } else {
        ui.painter().rect_stroke(
            rect,
            radius,
            Stroke::new(1., p.border),
            egui::StrokeKind::Inside,
        );
    }
    if digit {
        ui.painter().line_segment(
            [
                rect.left_bottom() + egui::vec2(5., -1.5),
                rect.right_bottom() + egui::vec2(-5., -1.5),
            ],
            Stroke::new(2.5, p.accent),
        );
    }
    let display = match ch {
        ' ' => "␠".into(),
        '\n' => "↵".into(),
        '\t' => "⇥".into(),
        c if c.is_control()
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}') =>
        {
            format!("U+{:04X}", c as u32)
        }
        c => c.to_string(),
    };
    let size = if sample {
        14.
    } else {
        (rect.width()
            * if display.chars().count() > 1 {
                0.17
            } else {
                0.65
            })
        .clamp(9., 48.)
    };
    let galley = ui.fonts_mut(|f| {
        let galley = f.layout_no_wrap(display.clone(), FontId::monospace(size), color);
        let scale = ((rect.width() - 6.).max(1.) / galley.size().x.max(1.))
            .min((rect.height() - if sample { 0. } else { 8. }).max(1.) / galley.size().y.max(1.));
        if scale < 1. {
            f.layout_no_wrap(display, FontId::monospace(size * scale), color)
        } else {
            galley
        }
    });
    ui.painter()
        .galley(rect.center() - galley.size() / 2., galley, color);
    let key = match ch {
        '0' => Some("large-zero"),
        '1' => Some("large-one"),
        'O' => Some("large-upper-o"),
        'I' => Some("large-upper-i"),
        'l' => Some("large-lower-l"),
        ' ' => Some("large-space"),
        _ => None,
    };
    let caption = key.map(|key| locale.text(key));
    if names && let Some(caption) = &caption {
        let mut job = egui::text::LayoutJob::simple(
            caption.clone(),
            fonts::regular(11.),
            p.text_muted,
            rect.width(),
        );
        job.wrap.max_rows = 1;
        let galley = ui.fonts_mut(|f| f.layout_job(job));
        ui.painter().galley(
            egui::pos2(rect.center().x - galley.size().x / 2., rect.bottom() + 5.),
            galley,
            p.text_muted,
        );
    }
    if position != 0 {
        let response = ui.interact(rect, ui.scope_id().with(position), egui::Sense::hover());
        response.widget_info(|| {
            egui::WidgetInfo::labeled(egui::Role::Label, true, format!("{position}: {ch}"))
        });
        response.on_hover_text(format!(
            "{position} · U+{:04X}{}",
            ch as u32,
            caption.map(|s| format!(" · {s}")).unwrap_or_default()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn short_desktop_windows_use_an_extra_group_when_the_value_can_fit() {
        assert_eq!(grid_layout(524., 252., 10, false, false).columns, 8);
        let short = grid_layout(524., 128., 10, false, false);
        assert_eq!(short.columns, 10);
        assert!(short.row_height <= 128. && short.names);
        assert_eq!(grid_layout(342., 600., 20, true, false).columns, 4);
        let tiny = grid_layout(147., 68., 1, true, true);
        assert!(tiny.cell_height + 18. <= 68.);
    }
    fn draw_frame(
        ctx: &egui::Context,
        input: egui::RawInput,
        body: impl FnMut(&mut egui::Ui),
    ) -> egui::FullOutput {
        let mut output = ctx.run_ui(input, body);
        output.textures_delta.clear();
        output
    }
    #[test]
    fn grid_fits_short_and_narrow_windows_and_virtualizes_long_values() {
        for size in [
            Vec2::new(195., 220.),
            Vec2::new(320., 320.),
            Vec2::new(390., 900.),
            Vec2::new(1320., 900.),
        ] {
            for count in [1, 19, 64, 4097] {
                let ctx = egui::Context::default();
                crate::ui_kit::setup(&ctx);
                let locale = Localizer::new(1).unwrap();
                let text = "Tq7#mL0v-Ox9!pR2"
                    .chars()
                    .cycle()
                    .take(count)
                    .collect::<String>();
                let source = Id::unique("secret");
                let mut state = State {
                    source: Some(source),
                    ..Default::default()
                };
                state.window.open = true;
                for frame in 0..3 {
                    let mut grid_viewport = Rect::NOTHING;
                    let output = draw_frame(
                        &ctx,
                        egui::RawInput {
                            screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, size)),
                            ..Default::default()
                        },
                        |ui| {
                            let r = state
                                .show(
                                    ui,
                                    crate::theme::THEMES[0].colors,
                                    Value {
                                        id: source,
                                        title: if count == 1 { "" } else { "Public fixture" },
                                        field: "Password",
                                        text: &text,
                                    },
                                    None,
                                    &locale,
                                    CopyState::Idle,
                                )
                                .unwrap();
                            grid_viewport = r.viewport;
                            if frame == 2 {
                                assert!(
                                    ctx.content_rect().expand(1.).contains_rect(r.rect),
                                    "{size:?}/{count}: {:?}",
                                    r.rect
                                );
                                for rect in
                                    [r.viewport, r.copy.rect, r.close.as_ref().unwrap().rect]
                                {
                                    assert!(
                                        r.rect.expand(1.).contains_rect(rect),
                                        "{size:?}/{count}: {rect:?} outside {:?}",
                                        r.rect
                                    );
                                }
                                assert!(
                                    r.copy.rect.top() >= r.viewport.bottom(),
                                    "{size:?}/{count}: actions {:?} overlap grid {:?}",
                                    r.copy.rect,
                                    r.viewport
                                );
                                assert!(!r.close.as_ref().unwrap().rect.intersects(r.copy.rect));
                                assert!(
                                    r.copy.rect.width() <= 44.
                                        && (r.copy.rect.width() - r.copy.rect.height()).abs() < 1.
                                );
                                assert!(
                                    r.rect.right() - r.copy.rect.right() <= M::LG + 1.,
                                    "copy must stay at the trailing edge"
                                );
                            }
                        },
                    );
                    if frame == 2 && count == 1 {
                        let expected = locale.text("vault-untitled");
                        assert!(output.shapes.iter().any(|shape| matches!(&shape.shape,egui::Shape::Text(t) if t.galley.job.text==expected)));
                        let glyph = output
                            .shapes
                            .iter()
                            .find_map(|shape| match &shape.shape {
                                egui::Shape::Text(t) if t.galley.job.text == text => Some(t),
                                _ => None,
                            })
                            .expect("the character must be visible");
                        assert!(
                            grid_viewport
                                .expand(1.)
                                .contains_rect(Rect::from_min_size(glyph.pos, glyph.galley.size())),
                            "the character must fit in the smallest viewport: {size:?}"
                        );
                    }
                    if frame == 2 && count == 4097 {
                        assert!(
                            output.shapes.len() < 1500,
                            "offscreen characters must not be painted"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn copy_feedback_keeps_the_grid_and_footer_in_place() {
        for size in [Vec2::new(320., 440.), Vec2::new(1320., 900.)] {
            for language in [0, 1, 8] {
                let ctx = egui::Context::default();
                crate::ui_kit::setup(&ctx);
                let locale = Localizer::new(language).unwrap();
                let source = Id::unique("secret");
                let mut state = State {
                    source: Some(source),
                    ..Default::default()
                };
                state.window.open = true;
                let mut geometry = None;
                for feedback in [
                    CopyState::Idle,
                    CopyState::Pending,
                    CopyState::Copied,
                    CopyState::Failed,
                ] {
                    for frame in 0..3 {
                        let _ = draw_frame(
                            &ctx,
                            egui::RawInput {
                                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, size)),
                                ..Default::default()
                            },
                            |ui| {
                                super::super::apply_density(ui.ctx(), false);
                                let output = state
                                    .show(
                                        ui,
                                        crate::theme::THEMES[0].colors,
                                        Value {
                                            id: source,
                                            title: "Public fixture",
                                            field: "Password",
                                            text: "Tq7#mL0v-Ox9!pR2wZ1l$aB4^nC8&dE3hJ6*K",
                                        },
                                        None,
                                        &locale,
                                        feedback,
                                    )
                                    .unwrap();
                                if frame == 2 {
                                    let current = (output.rect, output.viewport, output.copy.rect);
                                    if let Some(expected) = geometry {
                                        assert_eq!(current, expected, "{size:?}, {language}");
                                    } else {
                                        geometry = Some(current);
                                    }
                                    assert_eq!(
                                        output.copy.enabled(),
                                        feedback != CopyState::Pending
                                    );
                                }
                            },
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn resizing_an_open_viewer_keeps_its_source_and_focused_action() {
        let ctx = egui::Context::default();
        crate::ui_kit::setup(&ctx);
        let locale = Localizer::new(0).unwrap();
        let source = Id::unique("key");
        let text = "PUBLIC-TRANSFER-CODE-0123456789".repeat(3);
        let mut state = State {
            source: Some(source),
            ..Default::default()
        };
        state.window.open = true;
        let mut close_position = None;
        let mut floating_rect = None;
        for size in [
            Vec2::new(1320., 900.),
            Vec2::new(390., 900.),
            Vec2::new(320., 440.),
            Vec2::new(1320., 900.),
        ] {
            for frame in 0..3 {
                let _ = draw_frame(
                    &ctx,
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, size)),
                        ..Default::default()
                    },
                    |ui| {
                        let r = state
                            .show(
                                ui,
                                crate::theme::THEMES[0].colors,
                                Value {
                                    id: source,
                                    title: "Public fixture",
                                    field: "Key",
                                    text: &text,
                                },
                                None,
                                &locale,
                                CopyState::Idle,
                            )
                            .unwrap();
                        if frame == 2 {
                            close_position = Some(r.close.as_ref().unwrap().rect.center());
                            if size.x == 1320. {
                                if let Some(rect) = floating_rect {
                                    assert_eq!(
                                        r.rect, rect,
                                        "returning to desktop must restore floating bounds"
                                    );
                                } else {
                                    floating_rect = Some(r.rect);
                                }
                            }
                            assert!(
                                ctx.content_rect().expand(1.).contains_rect(r.rect),
                                "{size:?}: {:?}",
                                r.rect
                            );
                            assert_eq!(
                                ctx.memory(|m| m.focused()),
                                Some(r.close.as_ref().unwrap().id)
                            );
                        }
                    },
                );
            }
            assert!(state.is_open());
        }
        let pos = close_position.unwrap();
        for pressed in [true, false] {
            let _ = draw_frame(
                &ctx,
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(1320., 900.),
                    )),
                    events: vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: Default::default(),
                        },
                    ],
                    ..Default::default()
                },
                |ui| {
                    state.show(
                        ui,
                        crate::theme::THEMES[0].colors,
                        Value {
                            id: source,
                            title: "Public fixture",
                            field: "Key",
                            text: &text,
                        },
                        None,
                        &locale,
                        CopyState::Idle,
                    );
                },
            );
        }
        assert!(
            !state.is_open(),
            "the backdrop must stay below the resized window"
        );
    }
    #[test]
    fn escape_closes_viewer_and_restores_focus_without_changing_the_source() {
        let ctx = egui::Context::default();
        crate::ui_kit::setup(&ctx);
        let locale = Localizer::new(0).unwrap();
        let source = Id::unique("secret");
        let mut state = State::default();
        let text = "0OlI1 Жe\u{301}🔐\t\n-----BEGIN KEY-----\n";
        let mut opener = None;
        for frame in 0..7 {
            let _ = draw_frame(
                &ctx,
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(800., 700.))),
                    events: if frame == 3 {
                        vec![egui::Event::Key {
                            key: egui::Key::Escape,
                            physical_key: None,
                            pressed: true,
                            repeat: false,
                            modifiers: Default::default(),
                        }]
                    } else {
                        vec![]
                    },
                    ..Default::default()
                },
                |ui| {
                    let r = ui.button("Open");
                    opener = Some(r.id);
                    if frame == 0 {
                        state.source = Some(source);
                        state.window.open(&r);
                    }
                    state.show(
                        ui,
                        crate::theme::THEMES[0].colors,
                        Value {
                            id: source,
                            title: "Public fixture",
                            field: "Key",
                            text,
                        },
                        Some(&r),
                        &locale,
                        CopyState::Idle,
                    );
                },
            );
            if frame >= 3 {
                assert!(!state.is_open());
            }
        }
        assert_eq!(ctx.memory(|m| m.focused()), opener);
    }
}
