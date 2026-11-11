//! Orthogonal connectors stay in gutters, never behind node contents.
use eframe::egui::{self, Pos2, Rect, Vec2};

pub fn route(rects: &[Rect], from: usize, to: usize, horizontal: bool, lane: usize) -> Vec<Pos2> {
    let a = rects[from];
    let b = rects[to];
    if !horizontal {
        let x = a.left() - 12. - (lane % 4) as f32 * 4.;
        return vec![
            a.left_center(),
            egui::pos2(x, a.center().y),
            egui::pos2(x, b.center().y),
            b.left_center(),
        ];
    }
    if (a.left() - b.left()).abs() < 1. {
        if a.bottom() <= b.top() {
            return vec![a.center_bottom(), b.center_top()];
        }
        if b.bottom() <= a.top() {
            return vec![a.center_top(), b.center_bottom()];
        }
    }
    if b.left() - a.right() > a.width() {
        let floor = rects
            .iter()
            .map(|r| r.bottom())
            .fold(f32::NEG_INFINITY, f32::max)
            + 16.
            + (lane % 4) as f32 * 4.;
        return vec![
            a.right_center(),
            egui::pos2(a.right() + 12., a.center().y),
            egui::pos2(a.right() + 12., floor),
            egui::pos2(b.left() - 12., floor),
            egui::pos2(b.left() - 12., b.center().y),
            b.left_center(),
        ];
    }
    let start = a.right_center();
    let end = b.left_center();
    let x =
        ((start.x + end.x) / 2. + ((lane % 5) as f32 - 2.) * 5.).clamp(start.x + 8., end.x - 8.);
    vec![start, egui::pos2(x, start.y), egui::pos2(x, end.y), end]
}
pub fn paint(ui: &egui::Ui, path: &[Pos2], stroke: egui::Stroke) {
    if path.len() < 2 {
        return;
    }
    ui.painter().add(egui::Shape::line(path.to_vec(), stroke));
    let end = path[path.len() - 1];
    let direction = (end - path[path.len() - 2]).normalized();
    let normal = Vec2::new(-direction.y, direction.x);
    ui.painter().add(egui::Shape::convex_polygon(
        vec![
            end,
            end - direction * 7. + normal * 3.5,
            end - direction * 7. - normal * 3.5,
        ],
        stroke.color,
        egui::Stroke::NONE,
    ));
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connectors_do_not_cross_nodes() {
        for horizontal in [true, false] {
            let mut rects = Vec::new();
            for i in 0..10 {
                let layer = [0, 0, 0, 1, 1, 1, 2, 2, 2, 3][i];
                let slot = [0, 1, 2, 0, 1, 2, 0, 1, 2, 0][i];
                rects.push(Rect::from_min_size(
                    if horizontal {
                        egui::pos2(layer as f32 * 220., slot as f32 * 80.)
                    } else {
                        egui::pos2(40., i as f32 * 80.)
                    },
                    Vec2::new(156., 56.),
                ));
            }
            for (lane, (a, b)) in [
                (0, 3),
                (0, 4),
                (0, 5),
                (1, 3),
                (1, 4),
                (2, 3),
                (2, 4),
                (2, 8),
                (3, 6),
                (4, 6),
                (5, 6),
                (7, 6),
                (6, 9),
                (7, 9),
                (8, 9),
            ]
            .into_iter()
            .enumerate()
            {
                let path = route(&rects, a, b, horizontal, lane);
                for segment in path.windows(2) {
                    let delta = segment[1] - segment[0];
                    assert!(delta.x.abs() < 0.1 || delta.y.abs() < 0.1);
                    for step in 1..100 {
                        let point = segment[0] + delta * (step as f32 / 100.);
                        for rect in &rects {
                            assert!(
                                !rect.shrink(0.1).contains(point),
                                "edge {a}->{b} crosses {rect:?} at {point:?}"
                            );
                        }
                    }
                }
            }
        }
    }
}
