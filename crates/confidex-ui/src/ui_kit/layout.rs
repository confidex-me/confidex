//! Layout owns bounds and spacing; children supply content.
use super::{Metrics, fonts};
use crate::theme::Palette;
use eframe::egui::{self, Rect, Vec2};

pub fn content_column<R>(ui: &mut egui::Ui, body: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let (area, _) = ui.allocate_exact_size(ui.available_size(), egui::Sense::hover());
    let width = area.width().min(Metrics::CONTENT_WIDTH);
    let rect = Rect::from_center_size(area.center(), Vec2::new(width, area.height()));
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("content-column")
            .max_rect(rect)
            .layout(egui::Layout::top_down(egui::Align::Min)),
    );
    child.set_clip_rect(rect.expand(2.).intersect(ui.clip_rect()));
    body(&mut child)
}

pub fn scroll(
    ui: &mut egui::Ui,
    id: &str,
    horizontal: bool,
    body: impl FnOnce(&mut egui::Ui),
) -> egui::scroll_area::ScrollAreaOutput<()> {
    let area = if horizontal {
        egui::ScrollArea::horizontal().auto_shrink([false, true])
    } else {
        egui::ScrollArea::vertical().auto_shrink([false, false])
    };
    scroll_area(
        ui,
        id,
        area.min_scrolled_height(0.).min_scrolled_width(0.),
        usize::from(!horizontal),
        body,
    )
}
pub fn scroll_content(
    ui: &mut egui::Ui,
    id: &str,
    max_height: f32,
    body: impl FnOnce(&mut egui::Ui),
) -> egui::scroll_area::ScrollAreaOutput<()> {
    let mut output = scroll_area(
        ui,
        id,
        egui::ScrollArea::vertical()
            .max_height(max_height)
            .min_scrolled_height(max_height)
            .min_scrolled_width(0.)
            .auto_shrink([false, true]),
        1,
        body,
    );
    // egui reports the viewport before auto-shrink.
    output.inner_rect.max.y =
        output.inner_rect.top() + output.inner_rect.height().min(output.content_size.y);
    output
}
pub(crate) fn scroll_area<R>(
    ui: &mut egui::Ui,
    id: &str,
    area: egui::ScrollArea,
    axis: usize,
    body: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::scroll_area::ScrollAreaOutput<R> {
    let content_style = ui.style().clone();
    scroll_host(ui, id, axis, |ui| {
        area.id_salt(id).show(ui, |ui| {
            ui.set_style(content_style);
            body(ui)
        })
    })
}
pub fn scroll_rows(
    ui: &mut egui::Ui,
    id: &str,
    height: f32,
    row_height: f32,
    count: usize,
    mut body: impl FnMut(&mut egui::Ui, std::ops::Range<usize>),
) -> egui::scroll_area::ScrollAreaOutput<()> {
    let style = ui.style().clone();
    let overflow = count as f32 * (row_height + ui.spacing().item_spacing.y)
        - ui.spacing().item_spacing.y
        > height;
    scroll_host(ui, id, 1, |ui| {
        egui::ScrollArea::vertical()
            .id_salt(id)
            .max_height(height)
            .min_scrolled_height(0.)
            .min_scrolled_width(0.)
            .auto_shrink([false, false])
            .scroll_bar_visibility(if overflow {
                egui::scroll_area::ScrollBarVisibility::AlwaysVisible
            } else {
                egui::scroll_area::ScrollBarVisibility::AlwaysHidden
            })
            .show_rows(ui, row_height, count, |ui, range| {
                ui.set_style(style.clone());
                body(ui, range);
            })
    })
}
#[derive(Clone)]
struct ScrollFade {
    last_active: f64,
    offset: Vec2,
    bounds: Rect,
    bars: Option<egui::Id>,
}

pub fn set_reduced_motion(ctx: &egui::Context, reduced: bool) {
    ctx.data_mut(|data| data.insert_temp(egui::Id::unique("reduced-motion"), reduced));
    ctx.request_repaint();
}

fn scroll_host<R>(
    ui: &mut egui::Ui,
    id: &str,
    axis: usize,
    show: impl FnOnce(&mut egui::Ui) -> egui::scroll_area::ScrollAreaOutput<R>,
) -> egui::scroll_area::ScrollAreaOutput<R> {
    let key = ui.scope_id().with(("scroll-fade", id));
    let now = ui.input(|input| input.time);
    let mut fade = ui
        .ctx()
        .data_mut(|data| data.get_temp::<ScrollFade>(key))
        .unwrap_or(ScrollFade {
            last_active: now,
            offset: Vec2::ZERO,
            bounds: Rect::NOTHING,
            bars: None,
        });
    let (pointer, moved, pressed, scrolling) = ui.input(|input| {
        (
            input.pointer.latest_pos(),
            input
                .events
                .iter()
                .any(|event| matches!(event, egui::Event::PointerMoved(_))),
            input.pointer.any_pressed(),
            input.smooth_scroll_delta != Vec2::ZERO,
        )
    });
    let active = ui.is_enabled() && {
        let scrolling = pointer.is_some_and(|pos| fade.bounds.contains(pos)) && scrolling;
        let bar = fade.bars.is_some_and(|id| {
            (0_usize..2).any(|axis| {
                ui.ctx().is_being_dragged(id.with(axis))
                    || ui
                        .ctx()
                        .read_response(id.with(axis))
                        .is_some_and(|response| {
                            response.is_pointer_button_down_on()
                                || pointer.is_some_and(|pos| response.rect.contains(pos))
                                    && (moved || pressed)
                        })
            })
        });
        scrolling || bar
    };
    if active {
        fade.last_active = now;
    }
    let visible = now - fade.last_active < 5.;
    let reduced = ui.style().animation_time == 0.
        || ui
            .ctx()
            .data_mut(|data| data.get_temp::<bool>(egui::Id::unique("reduced-motion")))
            .unwrap_or(false);
    let opacity = ui.ctx().animate_bool_with_time_and_easing(
        key.with("opacity"),
        visible,
        if reduced { 0. } else { 0.2 },
        egui::emath::easing::cubic_in_out,
    );
    let output = ui.scope(|ui| {
        let spacing = ui.spacing_mut();
        spacing.scroll.floating = false;
        spacing.scroll.bar_width = 8.;
        spacing.scroll.bar_inner_margin = Metrics::SM;
        spacing.scroll.foreground_color = true;
        spacing.scroll.fade.strength = 0.;
        let muted = ui.visuals().weak_text_color();
        let visuals = ui.visuals_mut();
        visuals.widgets.inactive.fg_stroke.color = muted.gamma_multiply(opacity);
        visuals.widgets.hovered.fg_stroke.color = visuals
            .widgets
            .hovered
            .fg_stroke
            .color
            .gamma_multiply(opacity);
        visuals.widgets.active.fg_stroke.color = visuals
            .widgets
            .active
            .fg_stroke
            .color
            .gamma_multiply(opacity);
        visuals.extreme_bg_color = egui::Color32::TRANSPARENT;
        show(ui)
    });
    let offset = output.inner.state.clamped_offset();
    if offset != fade.offset {
        fade.last_active = now;
        ui.ctx().request_repaint();
    }
    fade.offset = offset;
    fade.bounds = output.response.rect;
    fade.bars = Some(output.inner.id);
    if now - fade.last_active < 5. {
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_secs_f64(
                (5. - (now - fade.last_active)).max(0.),
            ));
    }
    ui.ctx().data_mut(|data| data.insert_temp(key, fade));
    // ScrollArea consumes the wheel only while it can move. Own the remaining
    // delta at either boundary too, before an enclosing scroll area sees it.
    if ui.is_enabled() && ui.rect_contains_pointer(output.response.rect) {
        ui.input_mut(|input| {
            if ui.style().always_scroll_the_only_direction {
                input.smooth_scroll_delta = Vec2::ZERO;
            } else {
                input.smooth_scroll_delta[axis] = 0.;
            }
        });
    }
    output.inner
}

pub fn stack<R>(
    ui: &mut egui::Ui,
    gap: f32,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = gap;
        add(ui)
    })
}
pub fn row<R>(
    ui: &mut egui::Ui,
    gap: f32,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        add(ui)
    })
}
pub fn flow<R>(
    ui: &mut egui::Ui,
    gap: f32,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    ui.allocate_ui_with_layout(
        Vec2::new(ui.available_width(), 0.),
        egui::Layout::left_to_right(egui::Align::Center).with_main_wrap(true),
        |ui| {
            ui.spacing_mut().item_spacing = Vec2::splat(gap);
            add(ui)
        },
    )
}
pub fn columns(width: f32, min: f32, gap: f32, max: usize) -> usize {
    if !width.is_finite() || !min.is_finite() || !gap.is_finite() || min <= 0. || gap < 0. {
        return 1;
    }
    (((width + gap) / (min + gap)).floor() as usize).clamp(1, max.max(1))
}
pub struct SidebarPanel {
    pub sidebar: Option<egui::Ui>,
    pub content: egui::Ui,
    pub rect: Rect,
}
pub fn sidebar_panel(ui: &mut egui::Ui, p: Palette, id: &str, height: f32) -> SidebarPanel {
    let (rect, _) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let wide = rect.width() >= Metrics::PANEL_BREAKPOINT;
    ui.painter()
        .rect_filled(rect, Metrics::RADIUS, p.background);
    let inner = rect.shrink(1.);
    let sidebar = if wide {
        let area = Rect::from_min_size(inner.min, Vec2::new(Metrics::PANEL_NAV, inner.height()));
        ui.painter().rect_filled(
            area,
            egui::CornerRadius {
                nw: Metrics::RADIUS,
                sw: Metrics::RADIUS,
                ne: 0,
                se: 0,
            },
            p.surface,
        );
        ui.painter().vline(
            area.right(),
            area.y_range(),
            egui::Stroke::new(1., p.border),
        );
        let mut child = ui.new_child(
            egui::UiBuilder::new()
                .id_salt((id, "sidebar"))
                .max_rect(area.shrink(Metrics::MD))
                .layout(egui::Layout::top_down(egui::Align::Min)),
        );
        child.set_clip_rect(area.intersect(ui.clip_rect()));
        Some(child)
    } else {
        None
    };
    let area = Rect::from_min_max(
        egui::pos2(
            inner.left() + if wide { Metrics::PANEL_NAV } else { 0. },
            inner.top(),
        ),
        inner.max,
    );
    let mut content = ui.new_child(
        egui::UiBuilder::new()
            .id_salt((id, "content"))
            .max_rect(area.shrink(Metrics::LG))
            .layout(egui::Layout::top_down(egui::Align::Min)),
    );
    content.set_clip_rect(area.intersect(ui.clip_rect()));
    ui.painter().rect_stroke(
        rect,
        Metrics::RADIUS,
        egui::Stroke::new(1., p.border),
        egui::StrokeKind::Inside,
    );
    SidebarPanel {
        sidebar,
        content,
        rect,
    }
}
pub fn grid(
    ui: &mut egui::Ui,
    id: &str,
    count: usize,
    min: f32,
    max: usize,
    gap: f32,
    mut cell: impl FnMut(&mut egui::Ui, usize),
) -> usize {
    let cols = columns(ui.available_width(), min, gap, max);
    let width = ((ui.available_width() - gap * (cols - 1) as f32) / cols as f32).max(1.);
    ui.push_id(id, |ui| {
        ui.spacing_mut().item_spacing.y = gap;
        for start in (0..count).step_by(cols) {
            row(ui, gap, |ui| {
                for index in start..(start + cols).min(count) {
                    ui.push_id(index, |ui| {
                        ui.allocate_ui_with_layout(
                            Vec2::new(width, 0.),
                            egui::Layout::top_down(egui::Align::Min),
                            |ui| {
                                ui.set_min_width(width);
                                ui.set_max_width(width);
                                cell(ui, index);
                            },
                        );
                    });
                }
            });
        }
    });
    cols
}
pub fn split(
    ui: &mut egui::Ui,
    p: Palette,
    id: &str,
    ratio: &mut f32,
    height: f32,
    left: impl FnOnce(&mut egui::Ui),
    right: impl FnOnce(&mut egui::Ui),
) -> Rect {
    let (rect, _) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let divider = rect.left() + rect.width() * ratio.clamp(0.25, 0.75);
    let handle = Rect::from_center_size(
        egui::pos2(divider, rect.center().y),
        Vec2::new(Metrics::SM, rect.height()),
    );
    let response = ui
        .interact(handle, ui.scope_id().with(id), egui::Sense::drag())
        .on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
    if response.dragged()
        && let Some(pos) = response.interact_pointer_pos()
    {
        *ratio = ((pos.x - rect.left()) / rect.width()).clamp(0.25, 0.75);
    }
    ui.painter().vline(
        divider,
        rect.y_range(),
        egui::Stroke::new(
            if response.hovered() { 2. } else { 1. },
            if response.hovered() {
                p.accent
            } else {
                p.border
            },
        ),
    );
    for (area, add) in [
        (
            Rect::from_min_max(rect.min, egui::pos2(divider - Metrics::SM, rect.bottom())),
            Box::new(left) as Box<dyn FnOnce(&mut egui::Ui)>,
        ),
        (
            Rect::from_min_max(egui::pos2(divider + Metrics::SM, rect.top()), rect.max),
            Box::new(right),
        ),
    ] {
        let mut child = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(area)
                .layout(egui::Layout::top_down(egui::Align::Min)),
        );
        child.set_clip_rect(area.intersect(ui.clip_rect()));
        add(&mut child);
    }
    handle
}
pub struct PanelGeometry {
    pub content: Rect,
    pub footer: Rect,
}
pub fn scroll_panel(
    ui: &mut egui::Ui,
    p: Palette,
    id: &str,
    height: f32,
    body: impl FnOnce(&mut egui::Ui),
    footer: impl FnOnce(&mut egui::Ui),
) -> PanelGeometry {
    let (rect, _) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let footer_rect = Rect::from_min_max(
        egui::pos2(rect.left(), rect.bottom() - super::density(ui).control),
        rect.max,
    );
    let divider = footer_rect.top() - Metrics::LG;
    let body_rect = Rect::from_min_max(rect.min, egui::pos2(rect.right(), divider - Metrics::LG));
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(body_rect)
            .layout(egui::Layout::top_down(egui::Align::Min)),
    );
    child.set_clip_rect(body_rect.intersect(ui.clip_rect()));
    let viewport = scroll(&mut child, id, false, body).inner_rect;
    ui.painter().hline(
        footer_rect.x_range(),
        divider,
        egui::Stroke::new(1., p.border),
    );
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(footer_rect)
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
    );
    child.set_clip_rect(footer_rect.intersect(ui.clip_rect()));
    footer(&mut child);
    PanelGeometry {
        content: viewport,
        footer: footer_rect,
    }
}
pub fn cell(ui: &mut egui::Ui, p: Palette, label: &str, height: f32, outlines: bool) {
    let (rect, _) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), height),
        egui::Sense::hover(),
    );
    ui.painter()
        .rect_filled(rect, Metrics::FIELD_RADIUS, p.control);
    if outlines {
        ui.painter().rect_stroke(
            rect,
            Metrics::FIELD_RADIUS,
            egui::Stroke::new(1., p.accent),
            egui::StrokeKind::Inside,
        );
    }
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        label,
        fonts::medium(Metrics::LABEL),
        p.text,
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grid_columns_stay_bounded() {
        assert_eq!(columns(300., 160., 16., 4), 1);
        assert_eq!(columns(336., 160., 16., 4), 2);
        assert_eq!(columns(1000., 160., 16., 4), 4);
        assert_eq!(columns(f32::NAN, 160., 16., 4), 1);
    }
}

#[cfg(test)]
mod geometry_tests {
    use super::*;
    #[test]
    fn grid_cells_align_in_rows() {
        let ctx = egui::Context::default();
        crate::ui_kit::setup(&ctx);
        let mut positions = Vec::new();
        let mut painted = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(900., 600.))),
                ..Default::default()
            },
            |ui| {
                grid(ui, "geometry", 6, 152., 3, 16., |ui, i| {
                    positions.push(ui.cursor().min);
                    cell(
                        ui,
                        crate::theme::THEMES[0].colors,
                        &i.to_string(),
                        76.,
                        true,
                    );
                });
            },
        );
        painted.textures_delta.clear();
        assert_eq!(positions.len(), 6);
        for row in positions.chunks(3) {
            assert!((row[0].y - row[1].y).abs() < 0.1);
            assert!((row[1].y - row[2].y).abs() < 0.1);
        }
        assert!(positions[3].y >= positions[0].y + 76.);
    }
    #[test]
    fn flow_sizes_to_tags_without_shrinking_buttons() {
        let ctx = egui::Context::default();
        crate::ui_kit::setup(&ctx);
        let p = crate::theme::THEMES[0].colors;
        let mut painted = ctx.run_ui(egui::RawInput::default(), |ui| {
            let mut tag = Rect::NOTHING;
            let compact = flow(ui, 8., |ui| {
                tag = crate::ui_kit::record::tag(
                    ui,
                    p,
                    "work",
                    crate::ui_kit::record::TagRole::Neutral,
                )
                .rect;
            });
            assert!((compact.response.rect.height() - tag.height()).abs() < 0.1);
            assert!(tag.height() < Metrics::CONTROL);
            let controls = flow(ui, 8., |ui| {
                crate::ui_kit::button(ui, p, "Save", crate::ui_kit::ButtonRole::Primary, 0., true)
            });
            assert!(controls.inner.rect.height() >= Metrics::CONTROL);
            assert_eq!(ui.spacing().interact_size.y, Metrics::CONTROL);
        });
        painted.textures_delta.clear();
    }
}

#[cfg(test)]
mod scroll_tests {
    use super::*;
    fn fade_frame(
        ctx: &egui::Context,
        time: f64,
        axis: usize,
        events: Vec<egui::Event>,
    ) -> (Rect, u8, egui::Id) {
        let mut viewport = Rect::NOTHING;
        let mut id = egui::Id::NULL;
        let mut painted = ctx.run_ui(
            egui::RawInput {
                time: Some(time),
                events,
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(400., 300.))),
                ..Default::default()
            },
            |ui| {
                let area = if axis == 1 {
                    egui::ScrollArea::vertical()
                } else {
                    egui::ScrollArea::horizontal()
                };
                let output = scroll_area(
                    ui,
                    "fade-test",
                    area.auto_shrink([false, false]).scroll_bar_visibility(
                        egui::scroll_area::ScrollBarVisibility::AlwaysVisible,
                    ),
                    axis,
                    |ui| {
                        ui.allocate_space(if axis == 1 {
                            Vec2::new(100., 1400.)
                        } else {
                            Vec2::new(1400., 100.)
                        });
                    },
                );
                viewport = output.inner_rect;
                id = output.id;
            },
        );
        let alpha = painted
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Rect(rect)
                    if (rect.rect.size()[1 - axis] - 8.).abs() < 0.1
                        && rect.rect.min[1 - axis] >= viewport.max[1 - axis] =>
                {
                    Some(rect.fill.a())
                }
                _ => None,
            })
            .max()
            .unwrap_or(0);
        painted.textures_delta.clear();
        (viewport, alpha, id)
    }
    #[test]
    fn scrollbars_fade_after_five_seconds_and_keep_their_geometry() {
        for axis in [0, 1] {
            let ctx = egui::Context::default();
            crate::ui_kit::setup(&ctx);
            let (bounds, alpha, id) = fade_frame(&ctx, 0., axis, vec![]);
            assert!(alpha > 0);
            let (before, active, _) = fade_frame(&ctx, 4.9, axis, vec![]);
            assert_eq!(alpha, active);
            let (_, fading, _) = fade_frame(&ctx, 5.01, axis, vec![]);
            assert!(fading > 0 && fading < alpha);
            let mut hidden = 255;
            for frame in 1..20 {
                hidden = fade_frame(&ctx, 5.01 + frame as f64 / 60., axis, vec![]).1;
            }
            assert_eq!(hidden, 0);
            assert_eq!(bounds, before);
            let bar = ctx.read_response(id.with(axis)).unwrap().rect;
            let point = bar.center();
            let (_, returning, _) =
                fade_frame(&ctx, 5.4, axis, vec![egui::Event::PointerMoved(point)]);
            assert!(returning < alpha);
            assert!(fade_frame(&ctx, 5.42, axis, vec![]).1 > 0);
            fade_frame(
                &ctx,
                5.42,
                axis,
                vec![egui::Event::PointerButton {
                    pos: point,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                }],
            );
            let (after, held, _) = fade_frame(&ctx, 12., axis, vec![]);
            assert!(held > 0);
            assert_eq!(bounds, after);
        }
    }
    #[test]
    fn reduced_motion_changes_scrollbar_visibility_immediately() {
        let ctx = egui::Context::default();
        crate::ui_kit::setup(&ctx);
        set_reduced_motion(&ctx, true);
        let (bounds, alpha, id) = fade_frame(&ctx, 0., 1, vec![]);
        assert!(alpha > 0);
        assert_eq!(fade_frame(&ctx, 5.01, 1, vec![]).1, 0);
        let point = ctx.read_response(id.with(1_usize)).unwrap().rect.center();
        let (after, shown, _) = fade_frame(&ctx, 5.02, 1, vec![egui::Event::PointerMoved(point)]);
        assert!(shown > 0);
        assert_eq!(bounds, after);
    }
    #[test]
    fn scrollbars_reserve_space_outside_content() {
        let ctx = egui::Context::default();
        crate::ui_kit::setup(&ctx);
        for frame in 0..3 {
            let mut painted = ctx.run_ui(
                egui::RawInput {
                    time: Some(frame as f64),
                    screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(700., 600.))),
                    ..Default::default()
                },
                |ui| {
                    ui.set_width(320.);
                    let output = scroll(ui, "row-scroll-test", true, |ui| {
                        row(ui, 8., |ui| {
                            for _ in 0..5 {
                                ui.allocate_exact_size(Vec2::new(132., 64.), egui::Sense::hover());
                            }
                        });
                    });

                    assert!(output.inner_rect.height() >= 64.);
                    assert!(output.content_size.x > output.inner_rect.width());
                    if frame == 2 {
                        assert!(ui.min_rect().height() >= output.content_size.y + 8.);
                    }
                    let output = scroll(ui, "vertical-scroll-test", false, |ui| {
                        for _ in 0..20 {
                            ui.allocate_exact_size(
                                Vec2::new(ui.available_width(), 48.),
                                egui::Sense::hover(),
                            );
                        }
                    });
                    assert!(output.content_size.y > output.inner_rect.height());
                    if frame == 2 {
                        assert!(ui.min_rect().width() >= output.content_size.x + 8.);
                    }
                },
            );
            painted.textures_delta.clear();
        }
    }
}

#[cfg(test)]
mod container_tests {
    use super::*;
    #[test]
    fn card_padding_and_pinned_actions_share_bounds() {
        for (width, height) in [
            (260., 98.),
            (320., 98.),
            (900., 98.),
            (260., 300.),
            (320., 300.),
            (900., 300.),
        ] {
            let ctx = egui::Context::default();
            crate::ui_kit::setup(&ctx);
            for frame in 0..3 {
                let mut painted = ctx.run_ui(
                    egui::RawInput {
                        time: Some(frame as f64),
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(width, 600.),
                        )),
                        ..Default::default()
                    },
                    |ui| {
                        ui.set_width(width);
                        ui.spacing_mut().item_spacing.x = 0.;
                        let mut geometry = None;
                        let mut first = Rect::NOTHING;
                        let mut action = Rect::NOTHING;
                        let card =
                            crate::ui_kit::card(crate::theme::THEMES[0].colors).show(ui, |ui| {
                                assert_eq!(ui.spacing().item_spacing, Vec2::splat(Metrics::SM));
                                geometry = Some(scroll_panel(
                                    ui,
                                    crate::theme::THEMES[0].colors,
                                    "panel-bounds",
                                    height,
                                    |ui| {
                                        for i in 0..10 {
                                            let (rect, _) = ui.allocate_exact_size(
                                                Vec2::new(ui.available_width(), 48.),
                                                egui::Sense::hover(),
                                            );
                                            if i == 0 {
                                                first = rect;
                                            }
                                        }
                                    },
                                    |ui| {
                                        action = crate::ui_kit::button(
                                            ui,
                                            crate::theme::THEMES[0].colors,
                                            "Save",
                                            crate::ui_kit::ButtonRole::Primary,
                                            0.,
                                            true,
                                        )
                                        .rect;
                                    },
                                ));
                            });
                        let geometry = geometry.unwrap();
                        assert!((card.response.rect.width() - width).abs() < 0.1);
                        assert!((first.left() - card.response.rect.left() - 13.).abs() < 0.1);
                        assert!((action.left() - first.left()).abs() < 0.1);
                        assert!(geometry.content.bottom() + Metrics::LG <= geometry.footer.top());
                        assert!(geometry.footer.contains_rect(action));
                        assert!(card.response.rect.contains_rect(geometry.footer));
                        if frame == 2 {
                            assert!(geometry.content.right() + 8. <= geometry.footer.right());
                        }
                    },
                );
                painted.textures_delta.clear();
            }
        }
    }
    #[test]
    fn scroll_does_not_change_parent_style() {
        let ctx = egui::Context::default();
        crate::ui_kit::setup(&ctx);
        let mut painted = ctx.run_ui(egui::RawInput::default(), |ui| {
            let original = (
                ui.spacing().scroll.floating,
                ui.spacing().scroll.bar_width,
                ui.visuals().widgets.inactive.fg_stroke,
            );
            scroll(ui, "scoped-style", true, |ui| {
                assert_eq!(ui.spacing().scroll.floating, original.0);
                ui.label("Content");
            });
            assert_eq!(
                original,
                (
                    ui.spacing().scroll.floating,
                    ui.spacing().scroll.bar_width,
                    ui.visuals().widgets.inactive.fg_stroke
                )
            );
        });
        painted.textures_delta.clear();
    }
}

#[cfg(test)]
mod containment_tests {
    use super::*;
    #[test]
    fn bounded_content_below_a_long_record_keeps_a_reachable_viewport() {
        for content in [20_f32, 160., 700.] {
            let ctx = egui::Context::default();
            crate::ui_kit::setup(&ctx);
            let mut offset = 0.;
            for frame in 0..3 {
                let mut inner = None;
                let mut outer = None;
                let mut painted = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(Rect::from_min_size(
                            egui::Pos2::ZERO,
                            Vec2::new(600., 600.),
                        )),
                        ..Default::default()
                    },
                    |ui| {
                        let area = egui::ScrollArea::vertical()
                            .max_height(200.)
                            .vertical_scroll_offset(offset)
                            .auto_shrink([false, false]);
                        outer = Some(scroll_area(ui, "long-record", area, 1, |ui| {
                            ui.allocate_space(Vec2::new(100., 1000.));
                            inner = Some(scroll_content(ui, "history", 320., |ui| {
                                ui.allocate_space(Vec2::new(100., content));
                            }));
                        }));
                    },
                );
                painted.textures_delta.clear();
                let inner = inner.unwrap();
                let outer = outer.unwrap();
                assert!((inner.inner_rect.height() - content.min(320.)).abs() < 1.);
                assert!(outer.content_size.y >= 1000. + content.min(320.));
                if frame > 0 {
                    assert!(
                        outer.inner_rect.intersects(inner.inner_rect),
                        "{content}: {:?} {:?} offset {offset}",
                        outer.inner_rect,
                        inner.inner_rect
                    );
                }
                offset = (outer.content_size.y - outer.inner_rect.height()).max(0.);
            }
        }
    }
    fn frame(
        ctx: &egui::Context,
        content: f32,
        events: Vec<egui::Event>,
    ) -> (
        egui::scroll_area::ScrollAreaOutput<()>,
        egui::scroll_area::ScrollAreaOutput<()>,
    ) {
        frame_at(ctx, content, events, None)
    }
    fn frame_at(
        ctx: &egui::Context,
        content: f32,
        events: Vec<egui::Event>,
        offsets: Option<(f32, f32)>,
    ) -> (
        egui::scroll_area::ScrollAreaOutput<()>,
        egui::scroll_area::ScrollAreaOutput<()>,
    ) {
        let mut parent = None;
        let mut child = None;
        let mut painted = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(600., 600.))),
                events,
                ..Default::default()
            },
            |ui| {
                let mut area = egui::ScrollArea::vertical()
                    .max_height(240.)
                    .auto_shrink([false, true]);
                if let Some((offset, _)) = offsets {
                    area = area.vertical_scroll_offset(offset);
                }
                parent = Some(scroll_area(ui, "parent", area, 1, |ui| {
                    ui.add_space(120.);
                    let mut area = egui::ScrollArea::vertical()
                        .max_height(80.)
                        .auto_shrink([false, true]);
                    if let Some((_, offset)) = offsets {
                        area = area.vertical_scroll_offset(offset);
                    }
                    child = Some(scroll_area(ui, "child", area, 1, |ui| {
                        ui.allocate_space(Vec2::new(100., content));
                    }));
                    ui.add_space(900.);
                }));
            },
        );
        painted.textures_delta.clear();
        (parent.unwrap(), child.unwrap())
    }
    fn wheel(pos: egui::Pos2, delta: f32) -> Vec<egui::Event> {
        vec![
            egui::Event::PointerMoved(pos),
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                source: egui::MouseWheelSource::Unknown,
                phase: egui::TouchPhase::Move,
                delta: Vec2::new(0., delta),
                modifiers: Default::default(),
            },
        ]
    }
    #[test]
    fn inner_wheel_stays_contained_at_top_bottom_and_without_overflow() {
        for (content, offset, delta) in [(400., 0., 300.), (400., 320., -300.), (20., 0., -300.)] {
            let ctx = egui::Context::default();
            super::super::setup(&ctx);
            frame(&ctx, content, vec![]);
            frame_at(&ctx, content, vec![], Some((60., offset)));
            let (_, child) = frame(&ctx, content, vec![]);
            let point = child.inner_rect.left_top()
                + Vec2::new(100., content.min(child.inner_rect.height()) / 2.);
            for _ in 0..4 {
                let (parent, _) = frame(&ctx, content, wheel(point, delta));
                assert!(
                    (parent.state.clamped_offset().y - 60.).abs() < 0.1,
                    "content {content}, child offset {offset}, delta {delta}, parent {}, pointer {point:?}, child {:?}",
                    parent.state.clamped_offset().y,
                    child.inner_rect
                );
            }
            for _ in 0..20 {
                let (parent, _) = frame(&ctx, content, vec![]);
                assert!((parent.state.clamped_offset().y - 60.).abs() < 0.1);
            }
            let (parent, _) = frame(&ctx, content, vec![]);
            let outside = parent.inner_rect.left_top() + Vec2::splat(8.);
            let (parent, _) = frame(&ctx, content, wheel(outside, -120.));
            assert!(
                parent.state.clamped_offset().y > 60.,
                "wheel outside child must reach parent"
            );
        }
    }
}
